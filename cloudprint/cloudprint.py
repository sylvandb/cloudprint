#!/usr/bin/env python
# Copyright 2014 Jason Michalski <armooo@armooo.net>
#
# This file is part of cloudprint.
#
# cloudprint is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cloudprint is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with cloudprint.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import cups
import datetime
import hashlib
import json
import logging
import logging.handlers
import os
import re
import requests
import stat
import sys
import tempfile
import time
import uuid

import xmpp

XMPP_SERVER_HOST = 'talk.google.com'
XMPP_SERVER_PORT = 5223

SOURCE = 'Armooo-PrintProxy-1'
PRINT_CLOUD_SERVICE_ID = 'cloudprint'
CLIENT_LOGIN_URL = '/accounts/ClientLogin'
PRINT_CLOUD_URL = 'https://www.google.com/cloudprint/'

# period in seconds with which we should poll for new jobs via the HTTP api,
# when xmpp is connecting properly.
# 'None' to poll only on startup and when we get XMPP notifications.
# 'Fast Poll' is used as a workaround when notifications are not working.
POLL_PERIOD = 3600.0
FAST_POLL_PERIOD = 30.0

# wait period to retry when xmpp fails
FAIL_RETRY = 60

# how often, in seconds, to send a keepalive character over xmpp
KEEPALIVE = 600.0

LOGGER = logging.getLogger('cloudprint')
LOGGER.setLevel(logging.INFO)

CLIENT_ID = '607830223128-rqenc3ekjln2qi4m4ntudskhnsqn82gn.apps.googleusercontent.com'
CLIENT_KEY = 'T0azsx2lqDztSRyPHQaERJJH'


class CloudPrintAuth(object):
    _header = {'X-CloudPrint-Proxy': 'ArmoooIsAnOEM'}

    def __init__(self, auth_path):
        self.auth_path = auth_path
        self.guid = None
        self.email = None
        self.xmpp_jid = None
        self.exp_time = None
        self.refresh_token = None
        self._access_token = None

    @property
    def session(self):
        s = requests.session()
        s.params['access_token'] = self.access_token
        s.headers['Authorization'] = 'Authorization {0}'.format(s.params['access_token'])
        s.headers.update(self._header)
        return s

    @property
    def access_token(self):
        if datetime.datetime.now() > self.exp_time:
            self.refresh()
        return self._access_token

    def no_auth(self):
        return not os.path.exists(self.auth_path)

    def login(self, name, description, ppd):
        self.guid = str(uuid.uuid4())
        reg_data = requests.post(
            PRINT_CLOUD_URL + 'register',
            {
                'output': 'json',
                'printer': name,
                'proxy':  self.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
            },
            headers = self._header,
        ).json()
        print 'Goto {0} to clame this printer'.format(reg_data['complete_invite_url'])

        end = time.time() + int(reg_data['token_duration'])
        while time.time() < end:
            time.sleep(10)
            print 'trying for the win'
            poll = requests.get(
                reg_data['polling_url'] + CLIENT_ID,
                headers = self._header,
            ).json()
            if poll['success']:
                break
        else:
            print 'The login request timedout'

        self.xmpp_jid = poll['xmpp_jid']
        self.email = poll['user_email']
        print 'Printer clammed by {0}.'.format(self.email)

        token = requests.post(
            'https://accounts.google.com/o/oauth2/token',
            data={
                'redirect_uri': 'oob',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_KEY,
                'grant_type': 'authorization_code',
                'code': poll['authorization_code'],
            }
        ).json()
        self.refresh_token = token['refresh_token']

        self.save()
        self.refresh()

    def refresh(self):
        token = requests.post(
            'https://accounts.google.com/o/oauth2/token',
            data={
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_KEY,
                'grant_type': 'refresh_token',
                'refresh_token': self.refresh_token,
            }
        ).json()
        self._access_token = token['access_token']

        slop_time = datetime.timedelta(minutes=15)
        expires_in = datetime.timedelta(seconds=token['expires_in'])
        self.exp_time = datetime.datetime.now() + (expires_in - slop_time)

    def load(self):
        try:
            with open(self.auth_path) as auth_file:
                auth_data = json.load(auth_file)
        except OSError:
            pass
        else:
            self.guid = auth_data['guid']
            self.xmpp_jid = auth_data['xmpp_jid']
            self.email = auth_data['email']
            self.refresh_token = auth_data['refresh_token']

        self.refresh()

    def delete(self):
        try:
            os.unlink(self.auth_path)
        except OSError:
            pass

    def save(self):
            with open(self.auth_path, 'w') as auth_file:
                os.chmod(self.auth_path, stat.S_IRUSR | stat.S_IWUSR)
                json.dump({
                    'guid':  self.guid,
                    'email': self.email,
                    'xmpp_jid': self.xmpp_jid,
                    'refresh_token': self.refresh_token,
                    },
                    auth_file
                )


class CloudPrintProxy(object):

    def __init__(self, auth, verbose=True):
        self.auth = auth
        self.verbose = verbose
        self.sleeptime = 0
        self.include = []
        self.exclude = []

    def get_printers(self):
        r = self.auth.session.post(
            PRINT_CLOUD_URL + 'list',
            {
                'output': 'json',
                'proxy': self.auth.guid,
            },
        )
        try:
            printers = r.json()
        except ValueError:
            pinfo = []
            LOGGER.error("get_printers %s, bad json: %s, %s",
                time.strftime('%Y%m%d-%H%M%S'), r, r.content)
        else:
            pinfo = printers.get('printers', [])
            if self.verbose:
                LOGGER.debug("get_printers: good json: %s, %s", r, r.content)
                LOGGER.info("get_printers, %d@%s: %s",
                    len(pinfo),
                    time.strftime('%Y%m%d-%H%M%S'),
                    ', '.join(p['name'] for p in pinfo))
        return [PrinterProxy(self, p['id'], p['name']) for p in pinfo]

    def delete_printer(self, printer_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'delete',
            {
                'output': 'json',
                'printerid': printer_id,
           },
        ).raise_for_status()
        if self.verbose:
            LOGGER.info('Deleted printer ' + printer_id)

    def add_printer(self, name, description, ppd):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'register',
            {
                'output': 'json',
                'printer': name,
                'proxy':  self.auth.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
           },
        ).raise_for_status()
        if self.verbose:
            LOGGER.info('Added Printer ' + name)

    def update_printer(self, printer_id, name, description, ppd):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'update',
            {
                'output': 'json',
                'printerid': printer_id,
                'printer': name,
                'proxy': self.auth.guid,
                'capabilities': ppd.encode('utf-8'),
                'defaults': ppd.encode('utf-8'),
                'status': 'OK',
                'description': description,
                'capsHash': hashlib.sha1(ppd.encode('utf-8')).hexdigest(),
           },
        ).raise_for_status()
        if self.verbose:
            LOGGER.info('Updated Printer ' + name)

    def get_jobs(self, printer_id):
        docs = self.auth.session.post(
            PRINT_CLOUD_URL + 'fetch',
            {
                'output': 'json',
                'printerid': printer_id,
           },
        ).json()

        return docs.get('jobs', [])

    def finish_job(self, job_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output': 'json',
                'jobid': job_id,
                'status': 'DONE',
           },
        ).json()
        if self.verbose:
            LOGGER.info('Finished Job' + job_id)

    def fail_job(self, job_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'control',
            {
                'output': 'json',
                'jobid': job_id,
                'status': 'ERROR',
           },
        ).json()
        if self.verbose:
            LOGGER.info('Failed Job' + job_id)


class PrinterProxy(object):
    def __init__(self, cpp, printer_id, name):
        self.cpp = cpp
        self.id = printer_id
        self.name = name

    def get_jobs(self):
        LOGGER.info('Polling for jobs on ' + self.name)
        return self.cpp.get_jobs(self.id)

    def update(self, description, ppd):
        return self.cpp.update_printer(self.id, self.name, description, ppd)

    def delete(self):
        return self.cpp.delete_printer(self.id)


class App(object):
    def __init__(self, cups_connection=None, cpp=None, printers=None, pidfile_path=None):
        self.cups_connection = cups_connection
        self.cpp = cpp
        self.printers = printers
        self.pidfile_path = pidfile_path
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_timeout = 5

    def run(self):
        process_jobs(self.cups_connection, self.cpp)


#True if printer name matches *any* of the regular expressions in regexps
def match_re(prn, regexps, empty=False):
    if len(regexps):
        try:
            return re.match(regexps[0], prn, re.UNICODE) or match_re(prn, regexps[1:])
        except Exception:
            sys.stderr.write('cloudprint: invalid regular expression: ' + regexps[0] + '\n')
            sys.exit(1)
    else:
        return empty


def get_printer_info(cups_connection, printer_name):
    with open(cups_connection.getPPD(printer_name)) as ppd_file:
        ppd = ppd_file.read()
    #This is bad it should use the LanguageEncoding in the PPD
    #But a lot of utf-8 PPDs seem to say they are ISOLatin1
    ppd = ppd.decode('utf-8')
    description = cups_connection.getPrinterAttributes(printer_name)['printer-info']
    return ppd, description


def sync_printers(cups_connection, cpp):
    local_printer_names = set(cups_connection.getPrinters().keys())
    remote_printers = dict([(p.name, p) for p in cpp.get_printers()])
    remote_printer_names = set(remote_printers)

    #Include/exclude local printers
    local_printer_names = set([prn for prn in local_printer_names if match_re(prn, cpp.include, True)])
    local_printer_names = set([prn for prn in local_printer_names if not match_re(prn, cpp.exclude)])

    #New printers
    for printer_name in local_printer_names - remote_printer_names:
        try:
            ppd, description = get_printer_info(cups_connection, printer_name)
            cpp.add_printer(printer_name, description, ppd)
        except (cups.IPPError, UnicodeDecodeError):
            LOGGER.info('Skipping ' + printer_name)

    #Existing printers
    for printer_name in local_printer_names & remote_printer_names:
        ppd, description = get_printer_info(cups_connection, printer_name)
        remote_printers[printer_name].update(description, ppd)

    #Printers that have left us
    for printer_name in remote_printer_names - local_printer_names:
        remote_printers[printer_name].delete()


def process_job(cups_connection, cpp, printer, job):
    try:

        options = cpp.auth.session.get(job['ticketUrl']).json()
        try:
            del options['request']
        except KeyError:
            pass
        options = dict((str(k), str(v)) for k, v in options.items())

        pdf = cpp.auth.session.get(job['fileUrl'])

        with tempfile.NamedTemporaryFile() as tmp:

            for chunk in pdf.iter_content(65536):
                tmp.write(chunk)

            tmp.flush()
            cups_connection.printFile(printer.name, tmp.name, job['title'], options)

    except Exception:
        cpp.fail_job(job['id'])
        LOGGER.exception('ERROR ' + job['title'].encode('unicode-escape'))
    else:
        cpp.finish_job(job['id'])
        LOGGER.info('SUCCESS ' + job['title'].encode('unicode-escape'))


def process_jobs(cups_connection, cpp):
    xmpp_conn = xmpp.XmppConnection(keepalive_period=KEEPALIVE)

    while True:
        printers = cpp.get_printers()
        try:
            for printer in printers:
                for job in printer.get_jobs():
                    process_job(cups_connection, cpp, printer, job)

            if not xmpp_conn.is_connected():
                xmpp_conn.connect(XMPP_SERVER_HOST, XMPP_SERVER_PORT, cpp.auth)

            xmpp_conn.await_notification(cpp.sleeptime)

        except Exception:
            global FAIL_RETRY
            LOGGER.exception('ERROR: Could not Connect to Cloud Service. Will Try again in %d Seconds' % FAIL_RETRY)
            time.sleep(FAIL_RETRY)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='daemon', action='store_true',
                        help='enable daemon mode (requires the daemon module)')
    parser.add_argument('-l', dest='logout', action='store_true',
                        help='logout of the google account')
    parser.add_argument('-p', metavar='pid_file', dest='pidfile', default='cloudprint.pid',
                        help='path to write the pid to (default %(default)s)')
    parser.add_argument('-a', metavar='account_file', dest='authfile', default=os.path.expanduser('~/.cloudprintauth.json'),
                        help='path to google account ident data (default %(default)s)')
    parser.add_argument('-c', dest='authonly', action='store_true',
                        help='establish and store login credentials, then exit')
    parser.add_argument('-f', dest='fastpoll', action='store_true',
                        help='use fast poll if notifications are not working')
    parser.add_argument('-i', metavar='regexp', dest='include', default=[], action='append',
                        help='include local printers matching %(metavar)s')
    parser.add_argument('-x', metavar='regexp', dest='exclude', default=[], action='append',
                        help='exclude local printers matching %(metavar)s')
    parser.add_argument('-v', dest='verbose', action='store_true',
                        help='verbose logging')
    args = parser.parse_args()

    # if daemon, log to syslog, otherwise log to stdout
    if args.daemon:
        handler = logging.handlers.SysLogHandler()
        handler.setFormatter(logging.Formatter(fmt='cloudprint.py: %(message)s'))
    else:
        handler = logging.StreamHandler(sys.stdout)
    LOGGER.addHandler(handler)

    if args.verbose:
        LOGGER.info('Setting DEBUG-level logging')
        LOGGER.setLevel(logging.DEBUG)

    auth = CloudPrintAuth(args.authfile)
    if args.logout:
        auth.delete()
        LOGGER.info('logged out')
        return

    cups_connection = cups.Connection()
    cpp = CloudPrintProxy(auth)

    cpp.sleeptime = POLL_PERIOD
    if args.fastpoll:
        cpp.sleeptime = FAST_POLL_PERIOD

    cpp.include = args.include
    cpp.exclude = args.exclude

    printers = cups_connection.getPrinters().keys()
    if not printers:
        LOGGER.error('No printers found')
        return

    if auth.no_auth():
        name = printers[0]
        ppd, description = get_printer_info(cups_connection, name)
        auth.login(name, description, ppd)
    else:
        auth.load()

    sync_printers(cups_connection, cpp)

    if args.authonly:
        sys.exit(0)

    if args.daemon:
        try:
            from daemon import runner
        except ImportError:
            print 'daemon module required for -d'
            print '\tyum install python-daemon, or apt-get install python-daemon, or pip install python-daemon'
            sys.exit(1)

        # XXX printers is the google list
        app = App(
            cups_connection=cups_connection,
            cpp=cpp,
            pidfile_path=os.path.abspath(args.pidfile)
        )
        sys.argv = [sys.argv[0], 'start']
        daemon_runner = runner.DaemonRunner(app)
        daemon_runner.do_action()
    else:
        process_jobs(cups_connection, cpp)

if __name__ == '__main__':
    main()
