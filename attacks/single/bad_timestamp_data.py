#!/usr/bin/env python

import os
import random
import signal
import sys
import time
from utils import *

from scapy.all import send, sr1, sr, TCP, IP, Raw


def signal_handler(sig, frame):
    enable_outgoing_rst()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


disable_outgoing_rst()

client_port = random.randint(10000, 60000)
client_ISN = random.getrandbits(32)
#server_ISN = random.getrandbits(32)

tcpdump_p = start_dump_pcap(SERVER_IP, client_port, "BAD_TIMESTAMP_DATA")

syn_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN, options=[('Timestamp', (1000, 0)), ('NOP', 0), ('NOP', 0)])
#send(syn_pkt)
syn_ack_pkt = sr1(syn_pkt)
server_ISN = syn_ack_pkt[TCP].seq
server_ts = 0
for opt in syn_ack_pkt[TCP].options:
    if opt[0] == 'Timestamp':
        server_ts = opt[1][0]

ack_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1, options=[('Timestamp', (2000, server_ts)), ('NOP', 0), ('NOP', 0)])
send(ack_pkt)

time.sleep(0.5)

req_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1, options=[('Timestamp', (0, server_ts)), ('NOP', 0), ('NOP', 0)])/Raw(load=DUMMY_REQ)
send(req_pkt)

time.sleep(0.5)

req_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1, options=[('Timestamp', (4000, server_ts)), ('NOP', 0), ('NOP', 0)])/Raw(load=HTTP_REQ)
send(req_pkt)

time.sleep(0.5)

#raw_input()
end_dump_pcap(tcpdump_p)

enable_outgoing_rst()

