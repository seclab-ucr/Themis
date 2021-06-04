#!/usr/bin/env python3

import time
import os
from collections import Counter
import argparse


def parse_zeek_log(fpath):
    with open(fpath) as fin:
        data = fin.readlines()

    all_ambiguities = []
    total_connections = []
    all_ambiguity_cnt = []
    for row in data:
        row = row.strip()
        if row.startswith("[AMBIGUITY_COUNT]"):
            row = row.split(' ', 1)[1]
            ambiguities_str, curr_total_connections = row.rsplit(', ', 1)
            curr_ambiguities = list(set(ambiguities_str.split(', ')))
            ambiguity_cnt = len(curr_ambiguities)
            all_ambiguity_cnt.append(ambiguity_cnt)
            all_ambiguities.extend(curr_ambiguities)
            total_connections.append(int(curr_total_connections))

    ambiguities_counter = Counter(all_ambiguities)
    ambiguity_cnt_counter = Counter(all_ambiguity_cnt)
    print("Counts for ambiguities: %s" % str(ambiguities_counter))
    print("Counts for per-connection ambiguity occurrence: %s" % str(ambiguity_cnt_counter))
    print("Total number of connections: %d" % max(total_connections))


parser = argparse.ArgumentParser(description='Some args.')
parser.add_argument('--pcap-fpath', type=str, help='pcap file to parse.')
parser.add_argument('--date', type=str, help='date/id.')
parser.add_argument('--parse-log', action='store_true')
args = parser.parse_args()

before_unmodified_ts = time.time()
os.system("ZEEK_DEBUG_LOG_STDERR=1 ../robust-zeek/build/src/zeek -r %s ../effectiveness/detect-bad-keywords.bro > zeek.log" % args.pcap_fpath)
after_unmodified_ts = time.time()
unmodified_time = after_unmodified_ts - before_unmodified_ts

os.system("rm *.log")

before_robust_ts = time.time()
os.system("ZEEK_DEBUG_LOG_STDERR=1 ../robust-zeek/build/src/zeek -r %s ../effectiveness/detect-bad-keywords.bro -R > zeek.log" % args.pcap_fpath)
after_robust_ts = time.time()
robust_time = after_robust_ts - before_robust_ts

if args.parse_log:
    parse_zeek_log("zeek.log")

delta = (robust_time - unmodified_time) / unmodified_time
print("Robust: %f | Unmodified: %f | Delta Percentage: %f" % (robust_time, unmodified_time, delta))

os.system("mv zeek.log %s_zeek_log" % args.date)
os.system("rm *.log")
