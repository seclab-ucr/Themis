#!/usr/bin/env python3

import errno
import os
import random
import signal
import sys
import time

from time import sleep

from scapy.all import sr1, TCP, IP, Raw, hexdump, sr, send, conf, L3RawSocket

from z3 import *


START_FROM = 1

SYN = 0x02
RST = 0x04
ACK = 0x10

SERVER_IP = "192.168.100.2"
#SERVER_IP = "127.0.0.1"
SERVER_PORT = 5555

conf.L3socket=L3RawSocket

# bad keyword
HTTP_REQ = "A"


def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    enable_other_packets()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def disable_other_packets():
    os.system("iptables -t raw -A OUTPUT -p tcp --dport 5555 -m ttl ! --ttl-eq 163 -j DROP")

def enable_other_packets():
    os.system("iptables -t raw -D OUTPUT -p tcp --dport 5555 -m ttl ! --ttl-eq 163 -j DROP")


def get_value_from_model(m, d, size):
    val = [0] * size
    if is_K(m[d]):
        for i in range(size):
            val[i] = m[d].arg(i).as_long()
    elif isinstance(m[d], FuncInterp):
        for i in range(size):
            if i >= m[d].num_entries():
                break
            e = m[d].entry(i)
            assert e.num_args() == 1
            val[e.arg_value(0).as_long()] = e.value().as_long()
    return val

def solve_constraints(constraints, args={}):
    s = Solver()
    constraints = constraints.split('\n')
    constraints_new = []
    client_isn_var = None
    server_isn_var = None
    for line in constraints:
        if line and line != '(check-sat)' and line != '(exit)':
            constraints_new.append(line)
        if line.startswith("(declare-") and "tcp_seq_num1_" in line:
            client_isn_var = line.split()[1]
        if line.startswith("(declare-") and "tcp_svr_isn" in line:
            server_isn_var = line.split()[1]
    if 'client_isn' in args and client_isn_var:
        client_isn = args['client_isn']
        v = []
        for i in range(4):
            v.append(client_isn % 256)
            client_isn /= 256
        v.reverse()
        # client ISN is network-order because we symbolized a packet field
        constraints_new.append("(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (client_isn_var, v[0], client_isn_var, v[1], client_isn_var, v[2], client_isn_var, v[3]))
    if 'server_isn' in args and server_isn_var:
        server_isn = args['server_isn']
        v = []
        for i in range(4):
            v.append(server_isn % 256)
            server_isn /= 256
        # server ISN is host order because we symbolized a local variable
        constraints_new.append("(assert (and (= (select %s (_ bv0 32) ) #x%02x) (= (select %s (_ bv1 32) ) #x%02x) (= (select %s (_ bv2 32) ) #x%02x) (= (select %s (_ bv3 32) ) #x%02x) ) )" % (server_isn_var, v[0], server_isn_var, v[1], server_isn_var, v[2], server_isn_var, v[3]))
    constraints = '\n'.join(constraints_new)

    print(constraints)

    F = parse_smt2_string(constraints)
    #print(F.sexpr())
    s.add(F)
    res = s.check()
    print(res)
    if res == sat:
        example = {}
        m = s.model()
        print(m)
        for d in m:
            k = str(d)
            if 'tcp_seq_num' in k:
                example[k] = get_value_from_model(m, d, 4)
            elif 'tcp_ack_num' in k:
                example[k] = get_value_from_model(m, d, 4)
            elif 'tcp_doff_reserved_flags' in k:
                example[k] = get_value_from_model(m, d, 1)
            elif 'tcp_flags' in k:
                example[k] = get_value_from_model(m, d, 1)
            elif 'tcp_win' in k:
                example[k] = get_value_from_model(m, d, 2)
            elif 'tcp_urg_ptr' in k:
                example[k] = get_value_from_model(m, d, 2)

        return example

    return None

# update the packet with concrete example of packet with index `idx`
def update_pkt_with_example(pkt, example, idx):
    print("==========")
    for k, v in example.items():
        if 'tcp_header' + str(idx) in k:
            octets = example[k]
            print('tcp_header: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].seq = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
            pkt[TCP].ack = (octets[4] << 24) + (octets[5] << 16) + (octets[6] << 8) + octets[7]
            pkt[TCP].dataofs = ((octets[8] & 0xF0) >> 4)
            pkt[TCP].reserved = ((octets[8] & 0x0E) >> 1)
            pkt[TCP].flags = ((octets[8] & 0x01) << 8) + octets[9]
            #pkt[TCP].flags = octets[9]
            #pkt[TCP].flags = 'A'
            pkt[TCP].window = (octets[10] << 8) + octets[11]
            #pkt[TCP].chksum = (octets[12] << 8) + octets[13]
            pkt[TCP].urgptr = (octets[14] << 8) + octets[15]
            #pkt[TCP].payload = [ chr(o) for o in octets[16:] ]
        elif 'tcp_seq_num' + str(idx) in k:
            octets = example[k]
            print('tcp_seq_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].seq = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_ack_num' + str(idx) in k:
            octets = example[k]
            print('tcp_ack_num: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].ack = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
        elif 'tcp_doff_reserved_flags' + str(idx) in k:
            octets = example[k]
            print('tcp_doff_reserved_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].dataofs = octets[0] >> 4
            pkt[TCP].reserved = octets[0] & 0xf
        elif 'tcp_flags' + str(idx) in k:
            octets = example[k]
            print('tcp_flags: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].flags = octets[0]
        elif 'tcp_win' + str(idx) in k:
            octets = example[k]
            print('tcp_win: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].window = (octets[0] << 8) + octets[1]
        elif 'tcp_urg_ptr' + str(idx) in k:
            octets = example[k]
            print('tcp_urg_ptr: ' + ' '.join([ ('%02X' % o) for o in octets ]))
            pkt[TCP].urgptr = (octets[0] << 8) + octets[1]

    #ls(pkt)
    #pkt.show()
    #pkt.show2()
    #wireshark(pkt)
    #hexdump(pkt)
    #send(pkt)


def send_concrete_packets(example, packet_num, payload_len=0, bad_checksum=False, tcp_opts=None):
    #print(example)
    client_port = random.randint(10000,60000)

    # client initial sequence number
    #client_isn = random.getrandbits(32)
    client_isn = 0xdeadbeef
    # server initial sequence number
    server_isn = 0

    payload = 'A' * payload_len

    # send pre packets
    for i in range(1, packet_num + 1):
        print("---------Packet #%d---------" % i)

        tcp_options = []
        if tcp_opts and 'tcp_options' + str(i) in example:
            octets = example['tcp_options' + str(i)]
            if tcp_opts == 'mss':
                mss_val = (octets[0] << 8) + octets[1]
                tcp_options.append(('MSS', mss_val))
            elif tcp_opts == 'wscale':
                wscale_val = octets[0]
                tcp_options.append(('WScale', wscale_val)) 
            elif tcp_opts == 'sackok':
                tcp_options.append(('SAckOK', b''))
            elif tcp_opts == 'sack':
                sack_val1 = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                sack_val2 = (octets[4] << 24) + (octets[5] << 16) + (octets[6] << 8) + octets[7]
                tcp_options.append(('SAck', (sack_val1, sack_val2)))
            elif tcp_opts == 'timestamp':
                ts_val1 = (octets[0] << 24) + (octets[1] << 16) + (octets[2] << 8) + octets[3]
                ts_val2 = (octets[4] << 24) + (octets[5] << 16) + (octets[6] << 8) + octets[7]
                tcp_options.append(('Timestamp', (ts_val1, ts_val2)))
            elif tcp_opts == 'md5':
                tcp_options.append((19, bytes(octets[:16])))
            elif tcp_opts == 'fastopenreq':
                tcp_options.append((34, b''))
            elif tcp_opts == 'fastopen':
                tcp_options.append((34, bytes(octets[:8])))
            elif tcp_opts == 'expfastopenreq':
                tcp_options.append((254, b'\xf9\x89'))
            elif tcp_opts == 'expfastopen':
                tcp_options.append((254, b'\xf9\x89' + bytes(octets[:8])))
            elif tcp_opts == 'smc':
                tcp_options.append((254, b'\xe2\xd4\xc3\xd9'))
            else:
                assert False, "Invalid tcp_opts: %s" % tcp_opts
            
            tcp_options.append(('EOL', 0)) 

        if bad_checksum:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, chksum=0xffff, options=tcp_options)/Raw(load=payload)
        else:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, options=tcp_options)/Raw(load=payload)
        hexdump(pkt)

        update_pkt_with_example(pkt, example, i)
        pkt['IP'].ttl = 163 # to bypass the iptables rule

        hexdump(pkt)
        """
        if i == 1:
            reply_pkt = sr1(pkt, timeout=3)
            if reply_pkt and TCP in reply_pkt:
                hexdump(reply_pkt)
                # update isn_server with received reply_pkt
                server_isn = reply_pkt['TCP'].seq
            else:
                print("No SYN/ACK. Exit.")
                sys.exit(-1)
        else:
            send(pkt)
        """
        send(pkt)

        sleep(1)


def send_symbolic_packets(payload_len=0, bad_checksum=False, tcp_opts=None):
    client_port = random.randint(10000,60000)

    # client initial sequence number
    #client_isn = random.getrandbits(32)
    client_isn = 0xdeadbeef
    # server initial sequence number
    server_isn = 0

    tcp_options = []
    if tcp_opts:
        tcp_opts = tcp_opts.split(',')
        for opt in tcp_opts:
            if opt == 'mss':
                tcp_options.append(('MSS', 0))
            elif opt == 'wscale':
                tcp_options.append(('WScale', 0)) 
            elif opt == 'sackok':
                tcp_options.append(('SAckOK', b''))
            elif opt == 'sack':
                tcp_options.append(('SAck', (0, 0)))
            elif opt == 'timestamp':
                tcp_options.append(('Timestamp', (0, 0)))
            elif opt == 'md5':
                tcp_options.append((19, b'\xff' * 16))
            elif opt == 'fastopenreq':
                tcp_options.append((34, b''))
            elif opt == 'fastopen':
                tcp_options.append((34, b'\xff' * 8))
            elif opt == 'expfastopenreq':
                tcp_options.append((254, b'\xf9\x89'))
            elif opt == 'expfastopen':
                tcp_options.append((254, b'\xf9\x89' + b'\xff' * 8))
            elif opt == 'smc':
                tcp_options.append((254, b'\xe2\xd4\xc3\xd9'))
        
        tcp_options.append(('EOL', 0)) 

    i = 0
    while True:
        i += 1
        print("---------Sending symbolic packet #%d---------" % i)

        payload = 'A' * payload_len
        if bad_checksum:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, seq=client_isn, ack=server_isn, chksum=0xffff, options=tcp_options)/Raw(load=payload)
        else:
            pkt = IP(dst=SERVER_IP)/TCP(sport=client_port, dport=SERVER_PORT, seq=client_isn, ack=server_isn, options=tcp_options)/Raw(load=payload)

        pkt['IP'].ttl = 163 # to bypass the iptables rule
        send(pkt)
        time.sleep(0.2)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Probe S2E with packets generated by symbolic execution.')
    parser.add_argument('-f', dest='ce_file', type=argparse.FileType('r'), help='concrete example file')
    parser.add_argument('--pkt-file', type=argparse.FileType('r'), help='packet file')
    parser.add_argument('-s', dest='sym_pkt_num', type=int, default=1, help='number of symbolic packets to send')
    parser.add_argument('-p', dest='payload_len', type=int, default=0, help='TCP payload length (since data offset field may be symbolic, payload could also be treated as TCP options)')
    parser.add_argument('--tcp-opts', dest='tcp_opts', type=str, help='Send packet with TCP options')
    parser.add_argument('-b', dest='bad_checksum', default=False, action='store_true', help='Send packet with bad checksum')
    parser.add_argument('-t', dest='test_case_idx', type=int, help='test case index')
    args = parser.parse_args()

    disable_other_packets()

    if args.ce_file:
        i = 0
        for line in args.ce_file:
            i += 1
            if i < START_FROM:
                continue
            if args.test_case_idx and i < args.test_case_idx:
                continue
            entry = eval(line)
            # solve the constraints
            example = solve_constraints(entry['constraints'])
            packet_num = entry['packet_num']
            send_concrete_packets(example, packet_num, args.payload_len, args.bad_checksum, args.tcp_opts)
            if args.test_case_idx:
                break
            break
    elif args.pkt_file:
        i = 0
        for line in args.pkt_file:
            i += 1
            if i < START_FROM:
                continue
            if args.test_case_idx and i < args.test_case_idx:
                continue
            example = eval(line)
            # get packet num
            packet_num = 0
            for k in example:
                idx = 0
                for c in reversed(k):
                    if c.isdigit():
                        idx = idx * 10 + int(c)
                if idx > packet_num:
                    packet_num = idx
            send_concrete_packets(example, packet_num, args.payload_len, args.bad_checksum, args.tcp_opts)
            if args.test_case_idx:
                break
            break
    else:
        send_symbolic_packets(args.payload_len, args.bad_checksum, args.tcp_opts)

    enable_other_packets()
    
