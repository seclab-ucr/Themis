# Themis: Ambiguity-Aware Network Intrusion Detection based on Symbolic Model Comparison

_The paper is still in submission to a conference, so please keep the source code confidential. Thanks._

## Description

Themis is a systematic solution to defend against discrepancy-based NIDS evasion attacks.
It consists of an offline phase and an online phase. 
In the offline phase, it runs symbolic execution on various versions of the Linux kernel, 
and extracts symbolic models of TCP from the kernels; 
then it uses a constraint solver Z3 to automatically compare a pair of exatracted models and iteratively find all discrepancies between them.
After that, we integrate the discovered discrepancies into our robust NIDS, which is based on an open-source NIDS Zeek. 
In the online phase, our ambiguity-aware robust NIDS can fork its connection states when previously identified ambiguities are encountered in network traffic,
thus can successfully detect all evasion attacks based on those ambiguities. 

## Source Code

Currently we only make the source code of the online phase available.
Note that, the offline phase requires quite a lot of domain expertise in Linux TCP and symbolic execution. 
Please contact us for accessing the source code of the offline phase.

The structure of the repo is as follows:

```
/
├── attacks/                     Attack scripts
│   ├── composite/               Attacks using multiple discrepancies
│   └── single/                  Attacks using a single discrepancy 
├── effectiveness/               Scripts used for effectiveness evaluation
├── pcaps/                       Packet dump (pcap) files generated from attack scripts
├── perf/                        Scripts used for performance evaluation
├── robust-zeek/                 Our robust version of Zeek (ambiguities integrated) (based on Zeek 4.0)
├── scripts/                     Auxiliary scripts
├── ...
```

## Prerequisites

Zeek requires certain libraries to be installed. ([link](https://docs.zeek.org/en/current/install.html#prerequisites))

If you are using Debian/Ubuntu, you can use the following apt command, otherwise, please refer to the above link.

    sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev


## Installation

To compile and install Robust Zeek, you can use the following command.

    cd robust-zeek && ./configure && make && sudo make install


## Usage

1. To run Robust Zeek (-R robust mode)

       zeek -i <interface> -R

2. To run Robust Zeek and read packets from a pcap file

       zeek -r <pcap file> -R

3. To see how Robust Zeek can detect evasion attacks, we have pre-recorded attack traffic under `pcaps/` folder. `detect-bad-keywords.bro` is a rule file to detect the sensitive keyword in a HTTP request.

       zeek -r <pcap file>  effectiveness/detect-bad-keywords.bro -R
       
       (A notice.log file will be generated in the current folder if the keyword is detected.)

4. To enable detailed logging.

       ZEEK_DEBUG_LOG_STDERR=1 zeek -B dpd -r <pcap file> effectiveness/detect-bad-keywords.bro -R

