#!/usr/bin/env python3

import argparse
import os
import re
import subprocess
import sys


# SYMBEX_SCOPE is the scope that we run symbolic execution
# TCP_SCOPE is the enter TCP scope, we need to know this scope in order to disable timers and freeze time, etc.

SYMBEX_SCOPE = ('inet_connection_sock.o', 'tcp.o', 'tcp_ipv4.o', 'tcp_input.o', 'tcp_minisocks.o', 'tcp_timer.o', 'tcp_output.o')
TCP_SCOPE = ('inet_connection_sock.o', 'tcp.o', 'tcp_ipv4.o', 'tcp_input.o', 'tcp_minisocks.o', 'tcp_timer.o', 'tcp_output.o')

pattern = re.compile('[_A-Za-z0-9]+\.(part|isra)\.[0-9]+')


import argparse
parser = argparse.ArgumentParser(description='Generate mem ranges from compiled kernel.')
parser.add_argument('kernel_dir', type=str, help='Path of compiled kernel')
args = parser.parse_args()


symbex_functions = set()
for fname in SYMBEX_SCOPE:
    fpath = os.path.join(args.kernel_dir, 'net', 'ipv4', fname)
    output = subprocess.check_output("nm %s" % fpath, shell=True)
    output = output.decode('ascii').split('\n')
    for line in output:
        parts = line.split()
        if len(parts) == 3 and parts[1] in ('t', 'T'):
            #print(parts)
            name = parts[2]
            if pattern.match(name):
                name = name.split('.')[0]
            symbex_functions.add(name)


tcp_functions = set()
for fname in TCP_SCOPE:
    fpath = os.path.join(args.kernel_dir, 'net', 'ipv4', fname)
    output = subprocess.check_output("nm %s" % fpath, shell=True)
    output = output.decode('ascii').split('\n')
    for line in output:
        parts = line.split()
        if len(parts) == 3 and parts[1] in ('t', 'T'):
            #print(parts)
            name = parts[2]
            if pattern.match(name):
                name = name.split('.')[0]
            tcp_functions.add(name)


symbex_mem_ranges = []
tcp_mem_ranges = []

symbex_mr_start = None
symbex_mr_end = None
tcp_mr_start = None
tcp_mr_end = None

vmlinux_path = os.path.join(args.kernel_dir, 'vmlinux')
output = subprocess.check_output("nm %s | sort" % vmlinux_path, shell=True)
output = output.decode('ascii').split('\n')

all_functions = {}

for line in output:
    parts = line.split()
    if len(parts) == 3 and parts[1] in ('t', 'T'):
        if parts[2] not in all_functions:
            all_functions[parts[2]] = 0
        all_functions[parts[2]] += 1

for line in output:
    parts = line.split()
    if len(parts) == 3:
        addr, _, name = parts
        if pattern.match(name):
            name = name.split('.')[0]
        if name in symbex_functions:
            if symbex_mr_start is None and all_functions[name] == 1:
                #symbex_mr_start = hex(int(addr, 16))
                symbex_mr_start = addr
        else:
            if symbex_mr_start is not None:
                #symbex_mr_end = hex(int(addr, 16) - 1)
                symbex_mr_end = addr
                symbex_mem_ranges.append((symbex_mr_start, symbex_mr_end))
                symbex_mr_start = symbex_mr_end = None
            
        if name in tcp_functions:
            if tcp_mr_start is None and all_functions[name] == 1:
                #tcp_mr_start = hex(int(addr, 16))
                tcp_mr_start = addr
        else:
            if tcp_mr_start is not None:
                #tcp_mr_end = hex(int(addr, 16) - 1)
                tcp_mr_end = addr
                tcp_mem_ranges.append((tcp_mr_start, tcp_mr_end))
                tcp_mr_start = tcp_mr_end = None
        

print("Symbex mem ranges:")
for start, end in symbex_mem_ranges:
    print("(%s, %s)" % (start, end))

print("TCP mem ranges:")
for start, end in tcp_mem_ranges:
    print("(%s, %s)" % (start, end))






