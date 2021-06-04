#!/usr/bin/env python3

# Command-line interface for the Network Control Framework of Zeek, using Broker.

import logging
import netcontrol
import sys
import _thread
from yaml import load
try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader
import string
import re
import argparse
import sys

from subprocess import check_output
from subprocess import CalledProcessError
#from future.utils import viewitems

from enum import Enum, unique

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument('--listen', default="127.0.0.1", help="Address to listen on for connections. Default: 127.0.0.1")
    parser.add_argument('--port', default=9977, help="Port to listen on for connections. Default: 9977")
    parser.add_argument('--topic', default="zeek/event/netcontrol-example", help="Topic to subscribe to. Default: zeek/event/netcontrol-example")
    parser.add_argument('--file', default="commands.yaml", help="File to read commands from. Default: commands.yaml")
    parser.add_argument('--debug', const=logging.DEBUG, default=logging.INFO, action='store_const', help="Enable debug output")

    args = parser.parse_args()
    return args

class Listen:
    def __init__(self, queue, host, port, commands, **kwargs):
        self.logger = logging.getLogger(__name__)
        self.endpoint = netcontrol.Endpoint(queue, host, port)
        self.queuename = queue
        self.commands = commands
        self.use_threads = kwargs.get('use_threads', True)

    def listen_loop(self):
        self.logger.debug("Listen loop...")

        while 1==1:
            response = self.endpoint.getNextCommand()

            if response.type == netcontrol.ResponseType.AddRule:
                if self.use_threads:
                    _thread.start_new_thread(self._add_remove_rule, (response, ))
                else:
                    self._add_remove_rule(response)
            if response.type == netcontrol.ResponseType.RemoveRule:
                if self.use_threads:
                    _thread.start_new_thread(self._add_remove_rule, (response, ))
                else:
                    self._add_remove_rule(response)

    def _add_remove_rule(self, response):

        cmd = self.rule_to_cmd_dict(response.rule)

        if response.type == netcontrol.ResponseType.AddRule:
            type = 'add_rule'
        elif response.type == netcontrol.ResponseType.RemoveRule:
            type = 'remove_rule'
        else:
            self.logger.error("Internal error - incompabible rule type")
            type = 'unknown'

        if not ( type in self.commands):
            self.logger.error("No %s in commands", type)
            return

        commands = self.commands[type]

        output = ""

        self.logger.info("Received %s from Zeek: %s", type, cmd)

        for i in commands:
            currcmd = self.replace_command(i, cmd)
            output += "Command: "+currcmd+"\n"

            try:
                self.logger.info("Executing "+currcmd)
                cmdout = check_output(currcmd, shell=True)
                output += "Output: "+str(cmdout)+"\n"
                self.logger.debug("Command executed succefsully")
            except CalledProcessError as err:
                output = "Command "+currcmd+" failed with return code "+str(err.returncode)+" and output: "+str(err.output)
                self.logger.error(output)
                self.endpoint.sendRuleError(response, output)
                return
            except OSError as err:
                output = "Command "+currcmd+" failed with error code "+str(err.errno)+" ("+err.strerror+")"
                sel.logger.error(output)
                self.endpoint.sendRuleError(response, output)
                return

        if response.type == netcontrol.ResponseType.AddRule:
            self.logger.info("Sending rule_added to Zeek")
            self.endpoint.sendRuleAdded(response, output)
        else:
            self.logger.info("Sending rule_removed to Zeek")
            self.endpoint.sendRuleRemoved(response, output)

    def replace_single_command(self, argstr, cmds):
        reg = re.compile('\[(?P<type>.)(?P<target>.*?)(?:\:(?P<argument>.*?))?\]')
        #print argstr
        m = reg.search(argstr)

        if m == None:
            self.logger.error('%s could not be converted to rule', argstr)
            return ''

        type = m.group('type')
        target = m.group('target')
        arg = m.group('argument')

        if type == '?':
            if not ( target in cmds ):
                return ''
            elif arg == None:
                return cmds[target]

            # we have an argument *sigh*
            return re.sub(r'\.', cmds[target], arg)
        elif type == '!':
            if arg == None:
                self.logger.error("[!] needs argument for %s", argstr)
                return ''

            if not ( target in cmds ):
                return arg
            else:
                return ''
        else:
            self.logger.error("unknown command type %s in %s", type, argstr)
            return ''

    def replace_command(self, command, args):
        reg = re.compile('\[(?:\?|\!).*?\]')

        return reg.sub(lambda x: self.replace_single_command(x.group(), args), command)

    def rule_to_cmd_dict(self, rule):
        cmd = {}

        mapping = {
            'type': 'ty',
            'target': 'target',
            'expire': 'expire',
            'priority': 'priority',
            'id': 'id',
            'cid': 'cid',
            'entity.ip': 'address',
            'entity.mac': 'mac',
            'entity.conn.orig_h': 'conn.orig_h',
            'entity.conn.orig_p': 'conn.orig_p',
            'entity.conn.resp_h': 'conn.resp_h',
            'entity.conn.resp_p': 'conn.resp_p',
            'entity.flow.src_h': 'flow.src_h',
            'entity.flow.src_p': 'flow.src_p',
            'entity.flow.dst_h': 'flow.dst_h',
            'entity.flow.dst_p': 'flow.dst_p',
            'entity.flow.src_m': 'flow.src_m',
            'entity.flow.dst_m': 'flow.dst_m',
            'entity.mod.src_h': 'mod.src_h',
            'entity.mod.src_p': 'mod.src_p',
            'entity.mod.dst_h': 'mod.dst_h',
            'entity.mod.dst_p': 'mod.dst_p',
            'entity.mod.src_m': 'mod.src_m',
            'entity.mod.dst_m': 'mod.dst_m',
            'entity.mod.redirect_port': 'mod.port',
            'entity.i': 'mod.port',
        }

        for (k, v) in list(mapping.items()):
            path = k.split('.')
            e = rule
            for i in path:
                if e == None:
                    break
                elif i in e:
                    e = e[i]
                else:
                    e = None
                    break

            if e == None:
                continue

            if isinstance(e, tuple):
                cmd[v] = e[0]
                cmd[v+".proto"] = e[1]
            else:
                cmd[v] = e
                if isinstance(e, str):
                    spl = e.split("/")
                    if len(spl) > 1:
                        cmd[v+".ip"] = spl[0]
                        cmd[v+".net"] = spl[1]

        proto = mapping.get('entity.conn.orig_p.proto', mapping.get('entity.conn.dest_p.proto', mapping.get('entity.flow.src_p.proto', mapping.get('entity.flow.dst_p.proto', None))))
        if proto != None:
            entity['proto'] = proto

        return cmd

args = parseArgs()

stream = open(args.file, 'r')
config = load(stream, Loader=Loader)

logging.basicConfig(level=args.debug)

logging.info("Starting command-line client...")
zeekcon = Listen(args.topic, args.listen, int(args.port), config)
zeekcon.listen_loop()

