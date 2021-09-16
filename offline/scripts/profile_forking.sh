#!/bin/bash

TS=`date +%Y%m%d_%H%M%S`

if [ ! -z $1 ]; then
    S2E_OUTPUT_DIR=$1
else
    S2E_OUTPUT_DIR=s2e-last
fi

if [ -d "$S2E_OUTPUT_DIR/0" ]; then
    grep Forking $S2E_OUTPUT_DIR/*/info.txt > forking_$TS.raw
    cut -d\  -f13 forking_$TS.raw | sort | uniq -c | sort -nr > forking_$TS
else
    grep Forking $S2E_OUTPUT_DIR/info.txt > forking_$TS.raw
    cut -d\  -f10 forking_$TS.raw | sort | uniq -c | sort -nr > forking_$TS
fi

scripts/file_addr2line.py --vmlinux ./vmlinux forking_$TS


