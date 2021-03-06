# Themis: Ambiguity-Aware Network Intrusion Detection based on Symbolic Model Comparison

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

Note that, the offline phase requires quite a lot of domain expertise in Linux TCP and symbolic execution, and docs can be found [here](offline).
This README will focus on the online phase, so you may have a taste of how the ambiguity-aware NIDS works. 

The structure of the repo is as follows:

```
/
├── attacks/                     Attack scripts
│   ├── composite/               Attacks using multiple discrepancies
│   └── single/                  Attacks using a single discrepancy 
├── effectiveness/               Scripts used for effectiveness evaluation
├── offline/                     The implementation of the offline phase based on S2E and Z3
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
    
Alternatively, to enable debug, you can use the following command.

    cd robust-zeek && ./configure --enable-debug && make && sudo make install
    

## Usage

1. To run Robust Zeek (-R robust mode)

       zeek -i <interface> -R

2. To run Robust Zeek and read packets from a pcap file

       zeek -r <pcap file> -R

3. To see how Robust Zeek can detect evasion attacks, we have pre-recorded attack traffic under `pcaps/` folder. `detect-bad-keywords.bro` is a rule file to detect the sensitive keyword in a HTTP request.

       zeek -r <pcap file>  effectiveness/detect-bad-keywords.bro -R
       
       (A notice.log file will be generated in the current folder if the keyword is detected.)

4. To enable detailed logging (need to build zeek with debug enabled).

       ZEEK_DEBUG_LOG_STDERR=1 zeek -B dpd -r <pcap file> effectiveness/detect-bad-keywords.bro -R


## Publication

Please check our CCS'21 paper for more technical details[[PDF](https://zhongjie.me/files/ccs21_themis.pdf)]

Themis: Ambiguity-Aware Network Intrusion Detection based on Symbolic Model Comparison. 
Zhongjie Wang, Shitong Zhu, Keyu Man, Pengxiong Zhu, Yu Hao, Zhiyun Qian, Srikanth V. Krishnamurthy, Tom La Porta, Michael J. De Lucia. 
DOI:https://doi.org/10.1145/3460120.3484762

```
@inproceedings{wang2021themis,
  title={Themis: Ambiguity-Aware Network Intrusion Detection based on Symbolic Model Comparison},
  author={Wang, Zhongjie and Zhu, Shitong and Man, Keyu and Zhu, Pengxiong and Hao, Yu and Qian, Zhiyun and Krishnamurthy, Srikanth V and La Porta, Tom and De Lucia, Michael J},
  booktitle={CCS},
  year={2021}
}
```
