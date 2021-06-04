#!/usr/bin/env python

import os
import random
import signal
import sys
import time
from utils import *

from scapy.all import send, sr1, sr, TCP, IP, Raw


server_ip = SERVER_IP_54


def signal_handler(sig, frame):
    enable_outgoing_rst(server_ip)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


disable_outgoing_rst(server_ip)

client_port = random.randint(10000, 60000)
client_ISN = random.getrandbits(32)
#server_ISN = random.getrandbits(32)

tcpdump_p = start_dump_pcap(server_ip, client_port, "RST_AFTER_FIN")

syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN)
#syn_pkt.show()
#send(syn_pkt)
syn_ack_pkt = sr1(syn_pkt)
server_ISN = syn_ack_pkt[TCP].seq

ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)
send(ack_pkt)

time.sleep(0.5)

req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)/Raw(load=DUMMY_REQ[:20])
send(req_pkt)

time.sleep(0.5)

finack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='FA', seq=client_ISN + 21, ack=server_ISN + 1)
send(finack_pkt)

time.sleep(0.5)

rst_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='R', seq=client_ISN + 21)
send(rst_pkt)

time.sleep(0.5)


# second connection

client_ISN -= 100

syn_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='S', seq=client_ISN)
#syn_pkt.show()
#send(syn_pkt)
syn_ack_pkt = sr1(syn_pkt)
server_ISN = syn_ack_pkt[TCP].seq

ack_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)
send(ack_pkt)

time.sleep(0.5)

req_pkt = IP(dst=server_ip)/TCP(sport=client_port, dport=SERVER_PORT, flags='A', seq=client_ISN + 1, ack=server_ISN + 1)/Raw(load=HTTP_REQ)
send(req_pkt)

time.sleep(0.5)


#raw_input()
end_dump_pcap(tcpdump_p)

enable_outgoing_rst(server_ip)

