#!/usr/bin/env python3

import os
import re
import subprocess
import sys

from s2e_utils import *

p_state_id_str = "\d+ \[.*State (\d+)\]"
p_state_id = re.compile(p_state_id_str)
p_c_state_id_str = "\s*state (\d+)"
p_c_state_id = re.compile(p_c_state_id_str)
p_fork_str = "(\d+) [^\n]+?Forking state (\d) at pc = (0x.*?) .*\sstate (\d+).*?\sstate (\d+)"
p_fork = re.compile(p_fork_str, re.MULTILINE | re.DOTALL)
p_line_str = ": (onExecute|Entering|Leaving)"
p_line = re.compile(p_line_str)


s2e_out_dir = sys.argv[1]
sid = int(sys.argv[2])

multi_processing = False

if os.path.exists(s2e_out_dir + "/debug.txt"):
    # single-process
    multi_processing = False
elif os.path.exists(s2e_out_dir + "/0/debug.txt"):
    # multi-process
    multi_processing = True

s2e_output_files = get_s2e_output_files(s2e_out_dir)
reversed_fork_rel = get_reversed_fork_relations(s2e_output_files)

state_list = [ sid ]

while sid != 0:
    sid = reversed_fork_rel[sid]
    state_list.append(sid)

state_list.reverse()

print(state_list)

all_exec_lines = []
min_ts = 999999999999

state_debug_files = {}
forking_point = {}

for i in range(len(state_list)):
    sid = state_list[i]
    if i < len(state_list) - 1:
        next_sid = state_list[i + 1]
    else:
        next_sid = -1
    if multi_processing:
        output = subprocess.check_output('grep "State %d\]" %s/*/debug.txt | cut -d: -f1 | sort | uniq' % (sid, s2e_out_dir), shell=True)
        if not output:
            print("Reached the end of the log.")
            break
        output = output.decode()
        debug_files = output.strip().split('\n')
        debug_files = sorted(debug_files, key=lambda x: int(x.split('/')[1]))
    else:
        debug_files = ["%s/debug.txt" % s2e_out_dir]

    done = False
    for debug_file in debug_files:
        f = open(debug_file, 'r')
        content = f.read()
        f.close()
        for m in re.finditer(" Forking state %d at pc = (0x.*?) .*?\sstate (\d+).*?\sstate (\d+)" % sid, content, re.MULTILINE | re.DOTALL):
            pc = m.group(1)
            child_sid1 = int(m.group(2))
            child_sid2 = int(m.group(3))
            if child_sid1 == next_sid:
                print("%s: True" % pc)
                done = True
                break
            elif child_sid2 == next_sid:
                print("%s: False" % pc)
                done = True
                break
            elif child_sid1 == sid:
                print("%s: True" % pc)
            elif child_sid2 == sid:
                print("%s: False" % pc)
            else:
                assert False

        if done:
            break

#print(state_exec_lines)
#print(forking_point)


