#!/usr/bin/python

import sys
import dpkt
import struct
import socket

fe_server = '221.130.199.241'
DIR_IN = 'DIR_IN'
DIR_OUT = 'DIR_OUT'

class pkt_desc:
    def __init__(self):
        self.ts = None
        self.key = None
        self.dir = None
        self.flag = None
        self.seq = None
        self.ack = None
        self.sack = None
        self.leng = 0

    def __str__(self):
        return 'ts = %.6lf, key = %s, dir = %7s, flag = %s, seq = %d, ack = %d, leng = %d' % \
            (self.ts, self.key, self.dir, self.flag, self.seq, self.ack, self.leng)

def get_pkt_desc(ts, pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return None
    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return None

    tcp = ip.data
    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    src_port = tcp.sport
    dst_port = tcp.dport

    pd = pkt_desc()
    pd.ts = ts
    if src_ip == fe_server:
        pd.key = '%s.%d' % (dst_ip, dst_port)
        pd.dir = DIR_OUT
    elif dst_ip == fe_server:
        pd.key = '%s.%d' % (src_ip, src_port)
        pd.dir = DIR_IN
    else:
        return None
    
    return pd

def handle_pcap(filename):
    pcap = dpkt.pcap.Reader(open(filename))
    for ts, pkt in pcap:
        pd = get_pkt_desc(ts, pkt)
        if pd == None:
            continue

        pat = "Android "
        s = pkt.find(pat)
        if s == -1:
            continue
        b = s + len(pat)
        ver = pkt[b:b+5]
        print pd.key, ver
if __name__ == '__main__':
    if len(sys.argv) == 1:
        # handle_pcap('../samples/client-data-lost/117.140.12.79.6480.pcap')
        handle_pcap('../data/vse_fe_20141027.dump')
    else:
        handle_pcap(sys.argv[1])

