#!/usr/bin/python

import sys
import dpkt
import struct
import socket

DIR_IN = 'DIR_IN'
DIR_OUT = 'DIR_OUT'

fe_server = '221.130.199.241'
ip_list = list()

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

def get_pkt_key(pkt):
    eth = dpkt.ethernet.Ethernet(pkt)
    ip = eth.data
    tcp = ip.data

    src_ip = socket.inet_ntoa(ip.src)
    dst_ip = socket.inet_ntoa(ip.dst)
    src_port = tcp.sport
    dst_port = tcp.dport
    if src_ip == fe_server:
        key = '%s' % (dst_ip)
    else:
        key = '%s' % (src_ip)

    return key


def handle_pcap(filename):
    pcap = dpkt.pcap.Reader(open(filename))
    for  ts , pkt in pcap:
        if not is_valid_vse_pkt(pkt):
            # print 'non tcp pkt'
            continue
        key = get_pkt_key(pkt)
        ip_list.append(key)
        
def output_ip_info(filename):
    output = open(filename,'w')
    ip_items = list(set(ip_list))
    ip_items.sort()
    for item in ip_items:
       # print item
        item = str(item)
        output.write(item)
        output.write('\n')

    output.close()

if __name__ == '__main__':
    handle_pcap('/home/dengqian/360proj/data/vse_fe_20141023.dump')
    output_ip_info('/home/dengqian/360proj/ip1.txt')
    
        
