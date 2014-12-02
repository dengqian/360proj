#!/usr/bin/python

import sys
import dpkt
import struct
import socket

pfile = '../data/vse_fe_20141027.dump'

def get_pcap_flows(flows):
    opcap = list()
    ips = list()
    ports = list()
    for flow in flows:
        opcap.append(dpkt.pcap.Writer(open(flow + '.pcap', 'wb')))
        ips.append(socket.inet_aton('.'.join(flow.split('.')[:4])))
        ports.append(int(flow.split('.')[4]))

    ipcap = dpkt.pcap.Reader(open(pfile, 'rb'))
    for ts, pkt in ipcap:
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue
        ip = eth.data
        if ip.p != dpkt.ip.IP_PROTO_TCP:
            continue
        tcp = ip.data
        for i in range(len(flows)):
            if (ip.src == ips[i] and tcp.sport == ports[i]) or \
                    (ip.dst == ips[i] and tcp.dport == ports[i]):
                opcap[i].writepkt(pkt, ts)
                break

if __name__ == '__main__':
    if len(sys.argv) == 1:
        print 'flow name is needed'
        sys.exit()
    
    get_pcap_flows(sys.argv[1:])
