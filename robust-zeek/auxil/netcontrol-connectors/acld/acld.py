#!/usr/bin/env python3

# Acld interface for the Network Control Framework of Zeek, using Broker.

from __future__ import print_function

import argparse
import errno
import fcntl, os
import logging
import random
import re
import socket
import string
import sys
import ipaddress
import datetime
import time

import broker
import broker.zeek
from select import select
from logging.handlers import TimedRotatingFileHandler

MAX16INT = 2**16 - 1

def parseArgs():
    defaultuser = os.getlogin()
    defaulthost = socket.gethostname()
    defaultacldhost = '127.0.0.1'

    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default="127.0.0.1",
        help="Address to listen on for connections (default: %(default)s)")
    parser.add_argument('--port', type=int, default=9999,
        help="Port to listen on for connections (default: %(default)s)")
    parser.add_argument('--acld_host', metavar='HOST', action='append',
        help='ACLD hosts to connect to (default: %s)' % defaultacldhost)
    parser.add_argument('--acld_port', metavar='PORT', type=int, default=11775,
        help="ACLD port to connect to (default: %(default)s)")
    parser.add_argument('--log-user', default=defaultuser,
        help='user name provided to acld (default: %(default)s)')
    parser.add_argument('--log-host', default=defaulthost,
        help='host name provided to acld (default: %(default)s)')
    parser.add_argument('--topic', default="zeek/event/pacf",
        help="Topic to subscribe to. (default: %(default)s)")
    parser.add_argument('--debug', const=logging.DEBUG, action='store_const',
        default=logging.INFO,
        help="Enable debug output")
    parser.add_argument('--logfile',
        help="Filename of logfile. If not given, logs to stdout")
    parser.add_argument('--rotate', action="store_true",
        help="If logging to file and --rotate is specified, log will rotate at midnight")

    args = parser.parse_args()
    if not args.acld_host:
        args.acld_host = [defaultacldhost]
    return args

def hostportpair(host, port):
    """Host is an ip address or ip address and port,
       port is the default port.
       return a host-port pair"""
    tup = host.split(',', 1)
    if len(tup) == 2:
        host = tup[0]
        sport = tup[1]
        if not sport.isdigit():
            self.logger.error('%s: port must be numeric' % host)
            sys.exit(-1)
        port = int(sport)
    if port <= 0 or port > MAX16INT:
        self.logger.error('%s: port must be > 0 and < %d ' % (host, MAX16INT))
        sys.exit(-1)
    return host, port

class Listen(object):
    TIMEOUT_INITIAL = 0.25
    TIMEOUT_MAX = 8.0

    def __init__(self, queue, host, port, acld_hosts, acld_port, log_user, log_host):
        self.logger = logging.getLogger("brokerlisten")

        self.queuename = queue
        self.epl = broker.Endpoint()
        self.epl.listen(host, port)
        self.status_subscriber = self.epl.make_status_subscriber(True)
        self.subscriber = self.epl.make_subscriber(self.queuename)

        # Create a random list of host port pairs
        self.acld_hosts = []
        for host in acld_hosts:
            self.acld_hosts.append(hostportpair(host, acld_port))
        random.shuffle(self.acld_hosts)

        self.ident = '{%s@%s}' % (log_user, log_host)
        self.remote_ident = '?'

        self.sock = None

        self.waiting = {}
        self.buffer = ''

        self.acldstring = False
        self.acldcmd = {}

        # try to connect to acld
        self.connect()

    def connect(self):
        """Round robin across multiple aclds with exponential backoff"""
        if self.sock:
            self.sock.close()
            self.sock = None;
        # No delay on first retry with multiple aclds
        if len(self.acld_hosts) > 1:
            timeout = 0.0
        else:
            timeout = self.TIMEOUT_INITIAL
        while True:
            self.sock = socket.socket()
            hostpair = self.get_hostpair()
            self.remote_ident = '[%s].%d' % (hostpair[0], hostpair[1])
            self.logger.debug('%s Connecting' % self.remote_ident)
            try:
                self.sock.connect(hostpair)
            except socket.error as e:
                self.logger.error('%s %s' % (self.remote_ident, e.strerror))
                time.sleep(timeout)
                if not timeout:
                    timeout = self.TIMEOUT_INITIAL
                else:
                    timeout *= 2
                    if timeout > self.TIMEOUT_MAX:
                        timeout = self.TIMEOUT_MAX
                continue

            fcntl.fcntl(self.sock, fcntl.F_SETFL, os.O_NONBLOCK)
            self.logger.info('%s Connected' % self.remote_ident)
            break

    def get_hostpair(self):
        """Round robin multiple ACLD hosts"""
        hostport = self.acld_hosts.pop(0)
        self.acld_hosts.append(hostport)
        return hostport

    def listen_loop(self):
        self.logger.debug("Broker loop...")

        while 1==1:
            self.logger.debug("Waiting for broker message")
            readable, writable, exceptional = select(
                    [self.status_subscriber.fd(),
                     self.subscriber.fd(), self.sock],
                    [], [])

            if ( self.status_subscriber.fd() in readable ):
                self.logger.debug("Got broker status message")
                msg = self.status_subscriber.get()
                self._handle_broker_message(msg)
            elif ( self.subscriber.fd() in readable ):
                self.logger.debug("Got broker message")
                msg = self.subscriber.get()
                self._handle_broker_message(msg)
            elif ( self.sock in readable ):
                line = self.read_acld()
                while line != None:
                    self.logger.info("Received from ACLD: %s", line)
                    self.parse_acld(line)
                    line = self.read_acld()
                continue


    def parse_acld(self, line):
        line = line.rstrip("\r")
        if self.acldstring == False:
            items = line.split(" ")
            if len(items) == 3:
                ts, cookie, command = items
                more = None
            elif len(items) == 4:
                ts, cookie, command, more = items
            else:
                self.logger.error("Could not parse acld line: %s", line)
                return

            self.acldcmd = {'ts': ts, 'cookie': cookie, 'command': command}
            if more != None:
                self.acldstring = True
                self.acldcmd['comment'] = ""
                if more != "-":
                    self.logger.error("Parse error while parsing acld line: %s?", more)
            else:
                self.execute_acld()
        else:
            if line == ".":
                self.acldstring = False
                self.execute_acld()
            else:
                self.acldcmd['comment']+=line

    def execute_acld(self):
        cmd = self.acldcmd['command']
        cookie = int(self.acldcmd['cookie'])
        comment = self.acldcmd.get('comment', "")

        if cmd == "acld":
            # we get this when connecting
            self.logger.info('%s acld connection succesful' % self.remote_ident)
            return

        if cookie in self.waiting:
            msg = self.waiting[cookie]
            del self.waiting[cookie]

            if "-failed" in cmd:
                if re.search(".* is on the whitelist .*", comment):
                    self.rule_event("exists", msg['id'], msg['arule'], msg['rule'], comment)
                else:
                    self.rule_event("error", msg['id'], msg['arule'], msg['rule'], comment)
            elif re.search("Note: .* is already ", comment):
                self.rule_event("exists", msg['id'], msg['arule'], msg['rule'], comment)
            else:
                type = "added"
                if msg['add'] == False:
                    type = "removed"
                self.rule_event(type, msg['id'], msg['arule'], msg['rule'], comment)

        else:
            self.logger.warning("Got response to cookie %d we did not send. Ignoring", cookie)
            return

    def read_acld(self):
        try:
            data = self.sock.recv(4096)
            if len(data) == 0:
                self.logger.warning('%s Disconnected' % self.remote_ident)
                self.connect()
            self.buffer += data.decode("utf-8")
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                # socket not ready yet, just continue and see if something
                # is still in the buffer
                pass
            else:
                self.logger.error(e)
                sys.exit(-1)
                return

        if self.buffer.find("\r\n") != -1:
            line, self.buffer = self.buffer.split("\r\n", 1)
            return line
        else:
            return None

    def _handle_broker_message(self, m):
        if isinstance(m, broker.Status):
            if m.code() == broker.SC.PeerAdded:
                self.logger.info("Incoming connection established.")
                return

            return

        if type(m).__name__ != "tuple":
            self.logger.error("Unexpected type %s, expected tuple.", type(m).__name__)
            return

        if len(m) < 1:
            self.logger.error("Tuple without content?")
            return

        (topic, event) = m
        ev = broker.zeek.Event(event)
        event_name = ev.name()

        if event_name == "NetControl::acld_add_rule":
            self.add_remove_rule(event_name, ev.args(), True)
        elif event_name == "NetControl::acld_remove_rule":
            self.add_remove_rule(event_name, ev.args(), False)
        elif event_name == "NetControl::acld_rule_added":
            pass
        elif event_name == "NetControl::acld_rule_removed":
            pass
        elif event_name == "NetControl::acld_rule_error":
            pass
        elif event_name == "NetControl::acld_rule_exists":
            pass
        else:
            self.logger.error("Unknown event %s", event_name)
            return

    def add_remove_rule(self, name, m, add):
        print(m)
        if ( len(m) != 3 ) or ( not isinstance(m[0], broker.Count) ) or (not isinstance(m[1], tuple) ) or ( not isinstance(m[2], tuple) ):
            self.logger.error("wrong number of elements or type in tuple for acld_add|remove_rule")
            return

        id = m[0].value
        arule = self.record_to_record("acldrule", m[2])

        self.logger.info("Got event %s. id=%d, arule: %s", name, id, arule)

        cmd = arule['command'] + " " + str(arule['cookie']) + " " + arule['arg'] + " -"
        sendlist = [cmd, self.ident]
        if 'comment' in arule and arule['comment'] != None and len(arule['comment']) > 0:
            sendlist.append(arule['comment'])
        sendlist.append(".")

        self.waiting[arule['cookie']] = {'add': add, 'cmd': cmd, 'id': m[0], 'rule': m[1], 'arule': m[2]}
        self.logger.info("Sending to ACLD: %s", ", ".join(sendlist))
        self.sock.sendall(("\r\n".join(sendlist)+"\r\n").encode())

    def rule_event(self, event, id, arule, rule, msg):
        arule = self.record_to_record("acldrule", arule)
        self.logger.info("Sending to Zeek: NetControl::acld_rule_%s id=%d, arule=%s, msg=%s", event, id.value, arule, msg)

        ev = broker.zeek.Event("NetControl::acld_rule_"+event, id, rule, msg)
        self.epl.publish(self.queuename, ev)

    def record_to_record(self, name, m):
        if not isinstance(m, tuple):
            self.logger.error("Got non record element")

        rec = m

        elements = None
        if name == "acldrule":
            elements = ['command', 'cookie', 'arg', 'comment']
        else:
            self.logger.error("Unknown record type %s", name)
            return

        dict = {}
        for i in range(0, len(elements)):
            if rec[i] is None:
                dict[elements[i]] = None
                continue
            elif isinstance(rec[i], tuple):
                dict[elements[i]] = self.record_to_record(name+"->"+elements[i], rec[i])
                continue

            dict[elements[i]] = self.convert_element(rec[i])

        return dict

    def convert_element(self, el):
        if isinstance(el, broker.Count):
            return el.value

        if isinstance(el, ipaddress.IPv4Address):
            return str(el);

        if isinstance(el, ipaddress.IPv6Address):
            return str(el);

        if isinstance(el, ipaddress.IPv4Network):
            return str(el);

        if isinstance(el, ipaddress.IPv6Network):
            return str(el);

        if isinstance(el, broker.Port):
            p = str(el)
            ex = re.compile('([0-9]+)(.*)')
            res = ex.match(p)
            return (res.group(1), res.group(2))

        if isinstance(el, broker.Enum):
            tmp = el.name
            return re.sub(r'.*::', r'', tmp)

        if isinstance(el, list):
            return [convertElement(ell) for ell in el];

        if isinstance(el, datetime.datetime):
            return el

        if isinstance(el, datetime.timedelta):
            return el

        if isinstance(el, int):
            return el

        if isinstance(el, str):
            return el

        logger.error("Unsupported type %s", type(el) )
        return el;

args = parseArgs()
logger = logging.getLogger('')
logger.setLevel(args.debug)

handler = None

if args.logfile:
    if args.rotate:
        handler = TimedRotatingFileHandler(args.logfile, 'midnight')
    else:
        handler = logging.FileHandler(args.logfile);
else:
    handler = logging.StreamHandler(sys.stdout)

formatter = logging.Formatter('%(created).6f:%(name)s:%(levelname)s:%(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

logging.info("Starting acld.py...")
brocon = Listen(args.topic, args.listen, args.port, args.acld_host,
    args.acld_port, args.log_user, args.log_host)
try:
    brocon.listen_loop()
except KeyboardInterrupt:
    pass
