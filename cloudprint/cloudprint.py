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



VERBOSE = True


XMPP_SERVER_HOST = 'talk.google.com'
XMPP_SERVER_PORT = 5223

# in daemon mode, where/how to send syslog messages?
# if either HOST or PORT is None:
#   via /dev/log (if SOCKET is None)
#   via UDP to localhost:514 (if empty SOCKET)
# otherwise to specified host and port (must specify both)
SYSLOG_SERVER_HOST = None
SYSLOG_SERVER_PORT = None
# using UDP unless TCP is True
SYSLOG_SERVER_TCP = False
# but preferably to this unix domain socket
# (default: /dev/log, mac might want /var/run/syslog)
SYSLOG_SERVER_SOCKET = None
# Using log facility (defaults to LOG_USER)
SYSLOG_FACILITY = None

SOURCE = 'Armooo-PrintProxy-1'
PRINT_CLOUD_SERVICE_ID = 'cloudprint'
CLIENT_LOGIN_URL = '/accounts/ClientLogin'
PRINT_CLOUD_URL = 'https://www.google.com/cloudprint/'

# period in seconds with which we should poll for new jobs via the HTTP api,
# when xmpp is connecting properly.
# 'None' to poll only on startup and when we get XMPP notifications.
# 'Fast Poll' is used as a workaround when notifications are not working.
POLL_PERIOD = 3600
FAST_POLL_PERIOD = 30

# XMPP_POLL to interrupt XMPP wait by POLL_PERIOD
# but only poll for jobs every XMPP_POLL_PERIOD times
# used to revalidate XMPP connection more often than polling for jobs
XMPP_POLL_PERIOD = 6

# wait period to retry when xmpp fails
FAIL_RETRY = 60

# how often, in seconds, to send a keepalive character over xmpp
KEEPALIVE = 600

# failed job retries
RETRIES = 1

CLIENT_ID = '607830223128-rqenc3ekjln2qi4m4ntudskhnsqn82gn.apps.googleusercontent.com'
CLIENT_KEY = 'T0azsx2lqDztSRyPHQaERJJH'

LOGGER = None



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
        if int(time.time()) > self.exp_time:
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

        end = int(time.time()) + int(reg_data['token_duration'])
        while int(time.time()) < end:
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
        print 'Printer claimed by {0}.'.format(self.email)

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

        slop_time = 15 * 60
        expires_in = int(token['expires_in'])
        self.exp_time = int(time.time()) + (expires_in - slop_time)

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
        self._pinfo_time = 0
        self._pinfo = []

    def _get_pinfo(self):
        if self._pinfo and self._pinfo_time and (int(time.time()) - self._pinfo_time) < 300:
            return
        self._pinfo = []
        self._pinfo_time = int(time.time())
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
                time.strftime('%Y%m%d-%H%M%S', time.localtime(self._pinfo_time)), r, r.content)
        else:
            pinfo = printers.get('printers', [])
            if self.verbose:
                LOGGER.debug("get_printers: good json: %s, %s", r, r.content)
            LOGGER.info("get_printers @%s: %d%s",
                time.strftime('%Y%m%d-%H%M%S', time.localtime(self._pinfo_time)),
                len(pinfo),
                ' - ' + ', '.join(p['name'] for p in pinfo) if self.verbose else ''
            )
        self._pinfo = pinfo

    def get_printers(self):
        self._get_pinfo()
        return [PrinterProxy(self, p['id'], p['name']) for p in self._pinfo]

    def delete_printer(self, printer_id):
        self.auth.session.post(
            PRINT_CLOUD_URL + 'delete',
            {
                'output': 'json',
                'printerid': printer_id,
           },
        ).raise_for_status()
        if self.verbose:
            LOGGER.info('Deleted printer: %s', printer_id)

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
            LOGGER.info('Added Printer: %s', name)

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
            LOGGER.info('Updated Printer: %s', name)

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
            LOGGER.info('Finished Job: %s', job_id)

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
            LOGGER.info('Failed Job: %s', job_id)



class PrinterProxy(object):

    def __init__(self, cpp, printer_id, name):
        self.cpp = cpp
        self.printer_id = printer_id
        self.name = name

    def get_jobs(self):
        LOGGER.info('Polling for jobs on %s', self.name)
        return self.cpp.get_jobs(self.printer_id)

    def update(self, description, ppd):
        return self.cpp.update_printer(self.printer_id, self.name, description, ppd)

    def delete(self):
        return self.cpp.delete_printer(self.printer_id)



class ProxyApp(object):

    def __init__(self, sys_printers, cpp, sleeptime):
        self.sys_printers = sys_printers
        self.cpp = cpp
        self.sleeptime = sleeptime

    def run(self):
        self.process_jobs()


    def process_job(self, printer, job):

        job_retries = 0
        while True:
            try:

                options = self.cpp.auth.session.get(job['ticketUrl']).json()
                try:
                    del options['request']
                except KeyError:
                    pass
                options = dict((str(k), str(v)) for k, v in options.items())

                pdf = self.cpp.auth.session.get(job['fileUrl'])

                with tempfile.NamedTemporaryFile() as tmp:

                    for chunk in pdf.iter_content(65536):
                        tmp.write(chunk)

                    tmp.flush()
                    self.sys_printers.print_file(printer.name, tmp.name, job['title'], options)

            except Exception:
                job_retries += 1
                if job_retries > RETRIES:
                    self.cpp.fail_job(job['id'])
                    LOGGER.exception(
                        'ERROR failed after %d tries: %s', job_retries, job['title'].encode('unicode-escape'))
                    break
                LOGGER.exception('Job %s failed attempt %d, Will try again in %d seconds.',
                    job['title'].encode('unicode-escape'), job_retries, FAIL_RETRY)
                time.sleep(FAIL_RETRY)

            else:
                self.cpp.finish_job(job['id'])
                LOGGER.info('SUCCESS %s', job['title'].encode('unicode-escape'))
                break


    def process_jobs(self):

        xmpp_conn = xmpp.XmppConnection(keepalive_period=KEEPALIVE)

        while True:
            for printer in self.cpp.get_printers():
                for job in printer.get_jobs():
                    process_job(printer, job)

            xmpp_poll = XMPP_POLL_PERIOD or 1
            while xmpp_poll > 0:
                xmpp_poll -= 1
                try:
                    if not xmpp_conn.is_connected():
                        xmpp_conn.connect(XMPP_SERVER_HOST, XMPP_SERVER_PORT, self.cpp.auth)
                    if VERBOSE:
                        LOGGER.info('Waiting %ds for XMPP notification...', self.sleeptime)
                    xmpp_conn.await_notification(self.sleeptime)
                except Exception:
                    LOGGER.exception(
                        'ERROR: Could not Connect to XMPP Cloud Service. Will Try again in %d Seconds' % FAIL_RETRY)
                    time.sleep(FAIL_RETRY)



class SysPrinterError(Exception):
    pass


import cups
class SystemPrinters(object):

    def __init__(self, include=None, exclude=None):
        self._include = include
        self._exclude = exclude
        self.cups = cups.Connection()
        self.printers = None

    # return True if printer name matches *any* of the regular expressions in regexps
    @staticmethod
    def _match_re(prn, regexps, empty=False):
        if regexps:
            try:
                return re.match(regexps[0], prn, re.UNICODE) or self._match_re(prn, regexps[1:])
            except Exception:
                sys.stderr.write('cloudprint: invalid regular expression: ' + regexps[0] + '\n')
                sys.exit(1)
        else:
            return empty

    def _filter_printers(self, printers):
        #Include/exclude system printers
        printers = [prn for prn in printers if self._match_re(prn, self._include, True)]
        printers = [prn for prn in printers if not self._match_re(prn, self._exclude)]
        return printers


    def get_printer_names(self):
        if not self.printers:
            self.printers = self._filter_printers(self.cups.getPrinters().keys())
        return self.printers

    def get_printer_info(self, printer_name):
        try:
            description = self.cups.getPrinterAttributes(printer_name)['printer-info']
            with open(self.cups.getPPD(printer_name)) as ppd_file:
                ppd = ppd_file.read()
        except cups.IPPError as e:
            LOGGER.exception('System printer error:')
            raise SysPrinterError(str(e))
        #This is bad it should use the LanguageEncoding in the PPD
        #But a lot of utf-8 PPDs seem to say they are ISOLatin1
        try:
            dppd = ppd.decode('utf-8')
        except UnicodeDecodeError as e:
            LOGGER.exception('ppd UTF-8 decoding error:')
            raise SysPrinterError(str(e))
        return dppd, description

    def print_file(self, printer_name, file_name, job_title, options):
        self.cups.printFile(printer_name, file_name, job_title[:255], options)



def sync_printers(sys_printers, cpp):
    local_printer_names = set(sys_printers.get_printer_names())
    remote_printers = dict([(p.name, p) for p in cpp.get_printers()])
    remote_printer_names = set(remote_printers)

    #New printers
    for printer_name in local_printer_names - remote_printer_names:
        try:
            ppd, description = sys_printers.get_printer_info(printer_name)
            cpp.add_printer(printer_name, description, ppd)
        except SysPrinterError as e:
            LOGGER.info('Skipping: %s, %s', printer_name, e)

    #Printers that have left us
    for printer_name in remote_printer_names - local_printer_names:
        remote_printers[printer_name].delete()

    #Existing printers
    for printer_name in local_printer_names & remote_printer_names:
        ppd, description = sys_printers.get_printer_info(printer_name)
        remote_printers[printer_name].update(description, ppd)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', dest='daemon', action='store_true',
                        help='enable daemon mode (requires the daemon module)')
    parser.add_argument('-l', dest='logout', action='store_true',
                        help='logout of the google account')
    parser.add_argument('-p', metavar='pid_file', dest='pidfile', default='/run/cloudprint.pid',
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
    parser.add_argument('-D', dest='debug', action='store_true',
                        help='debug logging')
    return parser.parse_args()




def main():

    global LOGGER
    if LOGGER is None:
        LOGGER = logging.getLogger(PRINT_CLOUD_SERVICE_ID)
        LOGGER.setLevel(logging.INFO)

    args = parse_args()

    # if daemon, log to syslog, otherwise log to stdout
    if args.daemon:
        try:
            import daemon
            import daemon.pidfile
        except ImportError:
            print 'daemon module required for -d'
            print '\tyum install python-daemon, or apt-get install python-daemon, or pip install cloudprint[daemon]'
            sys.exit(1)

        kwargs = {}
        logaddr = (SYSLOG_SERVER_HOST, SYSLOG_SERVER_PORT)
        if None in logaddr:
            logaddr = '/dev/log' if SYSLOG_SERVER_SOCKET is None else SYSLOG_SERVER_SOCKET
        if logaddr:
            kwargs['address'] = logaddr
        if SYSLOG_SERVER_TCP:
            from socket import SOCK_STREAM
            kwargs['socktype'] = SOCK_STREAM
        if not SYSLOG_FACILITY is None:
            kwargs['facility'] = SYSLOG_FACILITY
        handler = logging.handlers.SysLogHandler(**kwargs)
        handler.setFormatter(logging.Formatter(fmt='cloudprint.py: %(message)s'))
    else:
        handler = logging.StreamHandler(sys.stdout)
    LOGGER.addHandler(handler)

    if args.debug:
        LOGGER.info('Setting DEBUG-level logging')
        LOGGER.setLevel(logging.DEBUG)
        args.verbose = True

    auth = CloudPrintAuth(args.authfile)
    if args.logout:
        auth.delete()
        LOGGER.info('logged out')
        return

    sys_printers = SystemPrinters(include=args.include, exclude=args.exclude)

    printers = sys_printers.get_printer_names()
    if not printers:
        LOGGER.error('No printers found')
        return

    if auth.no_auth():
        ppd, description = sys_printers.get_printer_info(printers[0])
        auth.login(printers[0], description, ppd)
    else:
        auth.load()

    if args.authonly:
        sys.exit(0)

    cpp = CloudPrintProxy(auth, verbose=bool(VERBOSE or args.verbose))

    sync_printers(sys_printers, cpp)

    app = ProxyApp(
        sys_printers=sys_printers,
        cpp=cpp,
        sleeptime = FAST_POLL_PERIOD if args.fastpoll else POLL_PERIOD,
    )

    if args.daemon:
        pidfile = daemon.pidfile.TimeoutPIDLockFile(
            path=os.path.abspath(args.pidfile),
            timeout=5,
        )
        with daemon.DaemonContext(pidfile=pidfile):
            app.run()
    else:
        app.run()




if __name__ == '__main__':

    main()
