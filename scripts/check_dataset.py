#!/usr/bin/python

import sys

from collections import defaultdict
from scapy.all import *


MAX_CONN_TIME = 10
WINDOW_SIZE = 29200


def four_tuple(packet):
    if packet.haslayer(TCP):
        return (packet[IP].src, packet[TCP].sport, packet[IP].dst, packet[TCP].dport)
    else:
        return (0, 0, 0, 0)

def reversed_four_tuple(packet):
    if packet.haslayer(TCP):
        return (packet[IP].dst, packet[TCP].dport, packet[IP].src, packet[TCP].sport)
    else:
        return (0, 0, 0, 0)

def sort_and_merge_seqs(seqs):
    if len(seqs) < 1:
        return seqs

    sorted_seqs = sorted(seqs, key=lambda x: x[0])
    merged_seqs = []
    seq_start, seq_end = sorted_seqs[0]
    for s, e in sorted_seqs[1:]:
        if seq_start <= s <= seq_end:
            if e > seq_end:
                seq_end = e
        else:
            merged_seqs.append((seq_start, seq_end))
            seq_start = s
            seq_end = e

    merged_seqs.append((seq_start, seq_end))

    return merged_seqs


conns = {}

stats = defaultdict(int)


# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap(sys.argv[1])

# Let's iterate through every packet
for packet in packets:
    if packet.haslayer(IP) and packet.haslayer(TCP):
        #import pdb; pdb.set_trace()
        ft = four_tuple(packet)
        rft = reversed_four_tuple(packet)
        if ft not in conns or packet.time - conn['last_time'] > MAX_CONN_TIME:
            conns[ft] = {'ack_seen': False, 'rcv_nxt': 0, 'last_seq': 0, 'recved_seqs': [], 'last_time': 0, 'sack_enabled': False}
        conn = conns[ft]

        plen = packet[IP].len - packet[IP].ihl * 4 - packet[TCP].dataofs * 4
        #print("Plen: %d" % plen)
        seq = packet[TCP].seq
        seq_end = packet[TCP].seq + plen + (1 if packet[TCP].flags.S else 0) + (1 if packet[TCP].flags.F else 0)

        if packet[TCP].flags.A:
            conn['ack_seen'] = True
        else:
            if packet[TCP].flags.S:
                if conn['ack_seen']:
                    packet.show()
                    stats['IN_WINDOW_SYN'] += 1
                    #assert False, "SYN recved after ACK"

                if packet[TCP].flags.F:
                    packet.show()
                    stats['SYN_FIN'] += 1
                    #assert False, "SYN/FIN recved"

        if packet[TCP].flags.R:
            if conn['sack_enabled'] and len(conn['recved_seqs']) > 1 and seq == conn['recved_seqs'][-1][1]:
                packet.show()
                stats['RST_RIGHTMOST_SACK'] += 1
                #assert False, "RST rightmost SACK"
            elif conn['rcv_nxt'] < seq < conn['rcv_nxt'] + WINDOW_SIZE:
                #packet.show()
                stats['IN_WINDOW_RST'] += 1
                #assert False, "RST in window"

        conn['recved_seqs'].append((seq, seq_end))
        conn['recved_seqs'] = sort_and_merge_seqs(conn['recved_seqs'])
            
        if plen > 0:
            if not packet[TCP].flags.A:
                #packet.show()
                stats['NO_ACK'] += 1
                #assert False, "Data packet without ACK flag"

        for opt in packet[TCP].options:
            if opt[0] in ('SAckOK', 'SAck'):
                conn['sack_enabled'] = True
                if rft in conns:
                    conns[rft]['sack_enabled'] = True
            elif opt[0] == 19:
                #packet.show()
                stats['MD5'] += 1
                #assert False, "MD5"

        conn['rcv_nxt'] = conn['recved_seqs'][0][1]
        conn['last_seq'] = seq_end
        conn['last_time'] = packet.time

print(stats)


