import os
import subprocess
import time
import datetime

PCAP_DIR = "../../pcaps/single"

SERVER_IP = "172.217.11.164"
SERVER_IP_44 = "18.144.28.131"
SERVER_IP_54 = "18.144.169.120"
LOCAL_SERVER_IP = "127.0.0.1"
#LOCAL_SERVER_IP = "192.168.100.2"
SERVER_PORT = 80
#SERVER_PORT = 5555

HTTP_REQ = "GET /AAAAAAAAAAAAAAAAAAAAAultrasurf HTTP/1.1\r\nHost: www.kankan.com\r\n\r\n"
DUMMY_REQ = "GET /AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA HTTP/1.1\r\nHost: www.kankan.com\r\n\r\n"


MOD32 = 2**32

def add(a, b):
    return (a + b) % MOD32

def sub(a, b):
        return (a - b) % MOD32

def before(a, b):
    if abs(a - b) > 2**31:
        if a < b:
            return False
        else:
            return True
    else:
        if a < b:
            return True
        else:
            return False

def after(a, b):
    return before(b, a)


def start_dump_pcap(ip, port, attack_type):
    pcap_fname = "%s/tcpdump_%s_%s.pcap" % (PCAP_DIR, attack_type, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    tcpdump_p = subprocess.Popen(['tcpdump', '-w', pcap_fname, "host %s and tcp port %d" % (ip, port)])
    time.sleep(1)
    return tcpdump_p

def start_dump_pcap_lo(ip, port, attack_type):
    pcap_fname = "%s/tcpdump_%s_%s.pcap" % (PCAP_DIR, attack_type, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    tcpdump_p = subprocess.Popen(['tcpdump', '-i', 'lo', '-w', pcap_fname, "host %s and tcp port %d" % (ip, port)])
    time.sleep(1)
    return tcpdump_p

def start_dump_pcap_qemubr0(ip, port, attack_type):
    pcap_fname = "%s/tcpdump_%s_%s.pcap" % (PCAP_DIR, attack_type, datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    tcpdump_p = subprocess.Popen(['tcpdump', '-i', 'qemubr0', '-w', pcap_fname, "host %s and tcp port %d" % (ip, port)])
    time.sleep(1)
    return tcpdump_p

def end_dump_pcap(tcpdump_p):
    time.sleep(1)
    tcpdump_p.terminate()
    os.system("pkill tcpdump")

def disable_outgoing_rst(server_ip=SERVER_IP):
    os.system("iptables -A OUTPUT -p tcp --dst %s --tcp-flags RST,ACK RST -m ttl ! --ttl-eq 163 -j DROP" % server_ip)

def enable_outgoing_rst(server_ip=SERVER_IP):
    os.system("iptables -D OUTPUT -p tcp --dst %s --tcp-flags RST,ACK RST -m ttl ! --ttl-eq 163 -j DROP" % server_ip)
