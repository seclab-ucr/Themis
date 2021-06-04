#!/usr/bin/python3

import glob
import os
import re
import subprocess


PCAPS_DIR = "../pcaps/composite"

pattern = re.compile('(\d+\.\d+)/(\d+\.\d+) \[dpd\]')


def run_zeek(pcap_file, robust_mode=True):
    if robust_mode:
        print("Robust Zeek.")
        cmd = "ZEEK_DEBUG_LOG_STDERR=1 ../robust-zeek/build/src/zeek -B dpd -r %s ../effectiveness/detect-bad-keywords.bro -R" % pcap_file
    else:
        print("Traditional Zeek.")
        cmd = "ZEEK_DEBUG_LOG_STDERR=1 ../robust-zeek/build/src/zeek -B dpd -r %s ../effectiveness/detect-bad-keywords.bro" % pcap_file

    #print(cmd)
    proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = proc.stderr.decode('ascii').split('\n')

    start_ts = end_ts = None

    for line in lines:
        m = pattern.match(line)
        if m:
            start_ts = float(m.group(2))
            break

    for line in reversed(lines):
        m = pattern.match(line)
        if m:
            end_ts = float(m.group(2))
            break

    print("Elapsed: %f" % (end_ts - start_ts))
    return end_ts - start_ts


fo = open('1.csv', 'w')

for i in range(1, 9):
    #x = glob.glob(PCAPS_DIR + "/tcpdump_COMPOSITE_%d_*" % i)
    #assert len(x) == 1, "None or multiple pcap files: % s" % x
    #pcap_file = x[0]
    pcap_file = os.path.join(PCAPS_DIR, '%d.pcap' %i)
    print(pcap_file)

    results1 = []
    results2 = []
    for n in range(10):
        t = run_zeek(pcap_file, False)
        results1.append(str(t))
        t = run_zeek(pcap_file, True)
        results2.append(str(t))

    fo.write(', '.join(results1) + '\n')
    fo.write(', '.join(results2) + '\n')

fo.close()



