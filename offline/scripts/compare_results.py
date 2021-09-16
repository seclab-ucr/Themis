#!/usr/bin/env python3

import os
import re
import sys


p_logline = re.compile('.*? \[(Node \d/\d - )?State \d+\] (.*)')

p_wl_llvm = re.compile("#0 0000 in tcg-llvm-\d+-(ffffffff[0-9a-f]+) \( \[(0x[0-9a-f]+)\]\)")
p_insert_symbol = re.compile("BaseInstructions: Inserted symbolic data @(.*) of size .*?: (.*=.*) pc=(.*)")
p_forking = re.compile("Forking state (\d+) at pc = (.*) at pagedir = (.*)")
p_forking_state_id = re.compile("state (\d+) (with condition .*)")

IGNORE_LINES = [
    'reqsk_timer_handler bypassed',
    'ip_build_and_send_pkt bypassed',
]


class FileInput:

    def __init__(self, filepath):
        self._f = open(filepath, 'r')
        self._eof = False
        # line number of the current line being processed
        self._line_no = 0

    def readline(self):
        while True:
            line = self._f.readline()
            self._line_no += 1
            if line == "":
                # EOF
                self._eof = True
                break

            while 'jiffies' in line:
                line = self._f.readline()
                self._line_no += 1

            skip_line = False
            for l in IGNORE_LINES:
                if l in line:
                    skip_line = True
                    break
            if skip_line:
                continue
            break

        return line

    def close(self):
        self._f.close()

    @property
    def line_no(self):
        return self._line_no

    @property
    def eof(self):
        return self._eof


result_dir1 = sys.argv[1]
result_dir2 = sys.argv[2]


def in_whitelist(s1, s2):
    if s1.startswith("Enabled branch coverage") and s2.startswith("Enabled branch coverage"):
        return True
    if s1.startswith("qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:Adding memory block") and s2.startswith("qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:qemu-system-x86_64:Adding memory block"):
        return True
    if s1.startswith("Adding memory block") and s2.startswith("Adding memory block"):
        return True
    m1 = p_wl_llvm.search(s1)
    m2 = p_wl_llvm.search(s2)
    if m1 and m2 and m1.group(1) == m2.group(1) and m1.group(2) != m2.group(2):
        return True
    if "SymTCP: sk_buff: " in s1 and "SymTCP: sk_buff: " in s2:
        return True
    if "sk_buff->data: " in s1 and "sk_buff->data: " in s2:
        return True
    if "SymTCP: TCP src port: " in s1 and "SymTCP: TCP src port: " in s2:
        return True
    m1 = p_insert_symbol.search(s1)
    m2 = p_insert_symbol.search(s2)
    if m1 and m2 and m1.group(1) != m2.group(1) and m1.group(2) == m2.group(2) and m1.group(3) == m2.group(3):
        return True
    m1 = p_forking.search(s1)
    m2 = p_forking.search(s2)
    if m1 and m2 and m1.group(2) == m2.group(2):
        return True
    if "SymTCP: req: " in s1 and "SymTCP: req: " in s2:
        return True
    if "SymTCP: req->snt_isn: " in s1 and "SymTCP: req->snt_isn: " in s2:
        return True
    if "SymTCP: sk: " in s1 and "SymTCP: sk: " in s2:
        return True
    if "SymTCP: full sk: " in s1 and "SymTCP: full sk: " in s2:
        return True
    m1 = p_forking_state_id.search(s1)
    m2 = p_forking_state_id.search(s2)
    if m1 and m2 and m1.group(2) == m2.group(2):
        return True

    return False


def do_compare(line1, line2):
    #print(line1)
    #print(line2)

    # remove leading timestamp
    m1 = p_logline.match(line1)
    m2 = p_logline.match(line2)
    if m1:
        #print(m1.groups())
        s1 = m1.group(2)
    else:
        s1 = line1

    if m2:
        #print(m2.groups())
        s2 = m2.group(2)
    else:
        s2 = line2

    if s1 != s2 and not in_whitelist(s1, s2):
        return False
    
    return True


f1 = FileInput(os.path.join(result_dir1, 'debug.txt'))
f2 = FileInput(os.path.join(result_dir2, 'debug.txt'))

while not f1.eof and not f2.eof:
    line1 = f1.readline()
    line2 = f2.readline()
    if line1 == "" or line2 == "":
        break
    if not do_compare(line1, line2):
        print("Line i %d j %d." % (f1.line_no, f2.line_no))
        print(line1)
        print(line2)
        input()

print("Done. i %d j %d" % (f1.line_no, f2.line_no))

f1.close()
f2.close()

