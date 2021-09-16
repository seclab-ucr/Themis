#!/bin/bash

if [ ! -z $1 ]; then
    S2E_OUTPUT_DIR=$1
else
    S2E_OUTPUT_DIR=s2e-last
fi

if [ -d "$S2E_OUTPUT_DIR/0" ]; then
    grep "^[[:space:]]*state [[:digit:]]*" $S2E_OUTPUT_DIR/*/info.txt | cut -d\  -f6 | sort -g | tail -n1
else
    grep "^[[:space:]]*state [[:digit:]]*" $S2E_OUTPUT_DIR/info.txt | cut -d\  -f6 | sort -g | tail -n1
fi


