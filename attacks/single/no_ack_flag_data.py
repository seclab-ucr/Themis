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

tcpdump_p = start_dump_pcap(SERVER_IP, client_port, "NO_ACK_FLAG_DATA")

syn_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN)
#send(syn_pkt)
syn_ack_pkt = sr1(syn_pkt)
server_ISN = syn_ack_pkt[TCP].seq

ack_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)
send(ack_pkt)

time.sleep(0.5)

req_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='', seq=client_ISN + 1, ack=server_ISN + 1)/Raw(load=DUMMY_REQ)
#req_pkt.show()
send(req_pkt)

time.sleep(0.5)

req_pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)/Raw(load=HTTP_REQ)
#req_pkt.show()
send(req_pkt)

time.sleep(0.5)

#raw_input()
end_dump_pcap(tcpdump_p)

enable_outgoing_rst()

