#!/usr/bin/python

import sys
import dpkt
import struct
import socket

DIR_IN = 'DIR_IN'
DIR_OUT = 'DIR_OUT'

fe_server = '221.130.199.241'
hash_table = dict()

class stat_struct:
    def __init__(self):
        self.start_time = 0
        self.in_time = list()
        self.out_time = 0

def is_valid_vse_pkt(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    if eth.type != dpkt.ethernet.ETH_TYPE_IP:
        return False
    ip = eth.data
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return False

    src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
    return src == fe_server or dst == fe_server

def get_payload_len(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp = ip.data
    length = ip.len - ip.hl*4 - tcp.off*4
    
    return length

def get_flags(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp = ip.data

    ret = ''
    if tcp.flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if tcp.flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if tcp.flags & dpkt.tcp.TH_RST:
        ret = ret + 'F'
    return ret

# return the key & the direction
def get_pkt_key(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp = ip.data

    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    src_port = tcp.sport
    dst_port = tcp.dport
    if src_ip == fe_server:
        key = '%s.%d' % (dst_ip, dst_port)
        dir = DIR_OUT
    else:
        key = '%s.%d' % (src_ip, src_port)
        dir = DIR_IN

    return (key, dir)

def parse_vse_conn(ts, key, dir, pkt):
    if key not in hash_table and 'S' in get_flags(pkt):
        hash_table[key] = stat_struct()
    if key not in hash_table:
        return

    stat = hash_table[key]

    l = get_payload_len(pkt)
    if dir == DIR_IN:
        if stat.start_time == 0:
            stat.start_time = ts
        if l > 0:
            stat.in_time.append(ts-stat.start_time)
    else:
        if l > 0:
            stat.out_time = ts-stat.start_time
    
    if 'F' in get_flags(pkt):
        if len(stat.in_time) != 0 and stat.out_time != 0:
            print key, '%.3f' % (stat.out_time), ' '.join([ '%.3f' % (_) for _ in stat.in_time ])
        del hash_table[key]

def handle_pcap(filename):
    pcap = dpkt.pcap.Reader(open(filename))
    for ts, pkt in pcap:
        if not is_valid_vse_pkt(pkt):
            # print 'non tcp pkt'
            continue
        key, dir = get_pkt_key(pkt)

        parse_vse_conn(ts, key, dir, pkt)

if __name__ == '__main__':
    handle_pcap(sys.argv[1])
    for k, v in hash_table.iteritems():
        if len(v.in_time) != 0 and v.out_time != 0:
            print k, '%.3f' % (v.out_time), ' '.join([ '%.3f' % (_) for _ in v.in_time ])
