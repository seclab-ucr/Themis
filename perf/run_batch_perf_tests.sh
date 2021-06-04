#!/bin/bash

python3 eval_perf.py --pcap-fpath ~/202004071400_TCP.pcap --date 0407 --parse-log > 0407.res
python3 eval_perf.py --pcap-fpath ~/202104251400_TCP.pcap --date 0425 --parse-log > 0425.res
python3 eval_perf.py --pcap-fpath ~/202104261400_TCP.pcap --date 0426 --parse-log > 0426.res
python3 eval_perf.py --pcap-fpath ~/202104271400_TCP.pcap --date 0427 --parse-log > 0427.res
python3 eval_perf.py --pcap-fpath ~/202104281400_TCP.pcap --date 0428 --parse-log > 0428.res
python3 eval_perf.py --pcap-fpath ~/202104291400_TCP.pcap --date 0429 --parse-log > 0429.res
python3 eval_perf.py --pcap-fpath ~/202104301400_TCP.pcap --date 0430 --parse-log > 0430.res
python3 eval_perf.py --pcap-fpath ~/202105011400_TCP.pcap --date 0501 --parse-log > 0501.res
