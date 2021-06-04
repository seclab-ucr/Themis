#!/bin/bash

rm tmp -rf
mkdir tmp
cd tmp

PCAP_DIR=../../pcaps

for PCAP_FILE in $PCAP_DIR/*; do

    ZEEK_DEBUG_LOG_STDERR=1 ../../robust-zeek/build/src/zeek -B dpd -r $PCAP_FILE ../../effectiveness/detect-bad-keywords.bro

    echo "Traditional Zeek..."
    echo "Working on " $PCAP_FILE "..."
    if test -f "notice.log"; then
        echo "Attack detected."
    else
        echo "Attack NOT detected."
        read -p "Press ENTER to continue.. "
    fi

    rm * -rf

    ZEEK_DEBUG_LOG_STDERR=1 ../../robust-zeek/build/src/zeek -B dpd -r $PCAP_FILE ../../effectiveness/detect-bad-keywords.bro -R

    echo "Robust Zeek..."
    echo "Working on " $PCAP_FILE "..."
    if test -f "notice.log"; then
        echo "Attack detected."
    else
        echo "Attack NOT detected."
        read -p "Press ENTER to continue.. "
    fi

    rm * -rf
done

rm tmp -rf

