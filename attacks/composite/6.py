#!/usr/bin/env python

import os
import random
import signal
import sys
import time
from utils import *

from scapy.all import send, sr1, sr, TCP, IP, Raw


#server_ip = SERVER_IP_44
#server_ip = LOCAL_SERVER_IP
server_ip = '192.168.100.2'
SERVER_PORT = 5555


def signal_handler(sig, frame):
    enable_outgoing_rst(server_ip)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


disable_outgoing_rst(server_ip)

client_port = random.randint(10000, 60000)
client_ISN = random.getrandbits(32)
#server_ISN = random.getrandbits(32)

tcpdump_p = start_dump_pcap_qemubr0(server_ip, client_port, "COMPOSITE_6")

# SYN+FIN
syn_fin_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='SF', seq=client_ISN + 100)
send(syn_fin_pkt)

time.sleep(0.5)

syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN, options=[('SAckOK', b''), ('NOP', 0), ('NOP', 0)])
#send(syn_pkt)
syn_ack_pkt = sr1(syn_pkt)
server_ISN = syn_ack_pkt[TCP].seq

ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)
send(ack_pkt)

time.sleep(0.5)

req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)/Raw(load=DUMMY_REQ[:20])
send(req_pkt)

time.sleep(0.5)

# in-window SYN
syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN + 22)
send(syn_pkt)

time.sleep(0.5)

# too old ACK num
req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 21, ack=server_ISN - 12345678, options=[('NOP', 0), ('NOP', 0), ('NOP', 0), ('NOP', 0)])/Raw(load=DUMMY_REQ[20:])
send(req_pkt)

time.sleep(0.5)

# in-window RST
rst_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_ISN + 22)
send(rst_pkt)

time.sleep(0.5)

# MD5
#rst_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_ISN + 21, options=[(19, b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\x11\x22\x33\x44\x55\x66'), ('NOP', 0), ('NOP', 0)])
#send(rst_pkt)

#time.sleep(0.5)

# no ACK flag
req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='', seq=client_ISN + 21, ack=server_ISN + 1)/Raw(load=DUMMY_REQ[20:])
send(req_pkt)

time.sleep(0.5)

# OOO packet
req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 31, ack=server_ISN + 1)/Raw(load=DUMMY_REQ[30:40])
send(req_pkt)

time.sleep(0.5)

# RST rightmost SACK
rst_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_ISN + 41)
send(rst_pkt)

time.sleep(0.5)

#req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 21, ack=server_ISN + 1)/Raw(load=DUMMY_REQ[20:])
#send(req_pkt)

#time.sleep(0.5)

for i in range(1000):
    req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 21 + i, ack=server_ISN + 1)/Raw(load='A')
    send(req_pkt)
    time.sleep(0.01)


#raw_input()
end_dump_pcap(tcpdump_p)

enable_outgoing_rst(server_ip)

