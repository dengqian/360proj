#!/usr/bin/python

import sys
import dpkt
import struct
import socket

from state_machine import *
_sm = state_machine()

fe_server = '221.130.199.241'
hash_table = dict()

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

    # flag
    pd.flag = 'A'
    if tcp.flags & dpkt.tcp.TH_SYN:
        pd.flag = 'S'
    if tcp.flags & dpkt.tcp.TH_FIN:
        pd.flag = 'F'
    if tcp.flags & dpkt.tcp.TH_RST:
        pd.flag = 'R'

    # seq, ack, sack
    pd.seq = tcp.seq
    pd.ack = tcp.ack
    for _ in dpkt.tcp.parse_opts(tcp.opts):
        if _[0] == 5: # sack
            sack = _[1]
            pd.sack = list()
            while len(sack) > 0:
                s = struct.unpack('!II', sack[:8])
                sack = sack[8:]
                pd.sack.append((s[0],s[1]))
            break

    pd.leng = ip.len - ip.hl*4 - tcp.off*4

    return pd

class stat_struct:
    def __init__(self):
        self.seq_base = 0
        self.ack_base = 0

        self.time_base = 0
        self.in_time = list()
        self.out_time = 0

        self.tcp_state = TCP_LISTEN

        self.seq_rcvd = 0
        self.ack_rcvd = 0
        self.seq_sent = 0
        self.ack_sent = 0

        self.seq_sack = list()
        self.ack_sack = list()

        # counters
        self.dup_syn = 0

        # self.rcv_retrans = list()
        self.snd_retrans = list()
        self.snd_reordering = list()
        self.snd_spurious = list()
        self.rcv_reordering = list()
        self.rcv_spurious = list()

        # self.dup_fin = 0

    def update_state(self, pd):
        # time
        if pd.dir == DIR_IN:
            if self.time_base == 0:
                self.time_base = pd.ts
            if pd.leng > 0:
                self.in_time.append(pd.ts-self.time_base)
        else:
            if pd.leng > 0:
                self.out_time = pd.ts-self.time_base

        # seq & ack
        if pd.dir == DIR_OUT:
            if self.tcp_state == TCP_SYN_RCVD:
                self.seq_base = pd.seq

            if self.seq_base == 0:
                print 'error, seq_base should not be 0'

            seq = pd.seq - self.seq_base
            self.seq_sent = max(seq, self.seq_sent)
            self.ack_sent = pd.ack - self.ack_base
            # handle seq
            l = pd.leng + int(pd.flag == 'S' or pd.flag == 'F')
            if l > 0 and seq+l <= self.seq_sent:
                # retrans
                self.snd_retrans.append((seq,seq+l))

            # handle ack
            if pd.sack != None:
                for p_ in pd.sack:
                    p = (p_[0]-self.ack_base, p_[1]-self.ack_base)
                    if p[1] <= self.ack_sent:
                        self.rcv_spurious.append(p)
                    else:
                        self.rcv_reordering.append(p)
        else:
            if self.tcp_state == TCP_LISTEN:
                self.ack_base = pd.seq

            if self.ack_base == 0:
                print 'error, ack_base should not be 0'

            seq = pd.seq - self.ack_base
            ack = pd.ack - self.seq_base
            l = pd.leng + int(pd.flag == 'S' or pd.flag == 'F')
            # handle seq
            if seq == self.seq_rcvd:
                self.seq_rcvd = max(self.seq_rcvd, seq+l)
                ok = True
                while ok:
                    ok = False
                    for p in self.rcv_reordering:
                        if p[0] == self.seq_rcvd:
                            self.seq_rcvd = p[1]
                            ok = True
            ## XXX Since server supports SACK, we need not record them here.
            # if seq > self.seq_rcvd:
            #     self.rcv_reordering.append((seq,seq+l))
            # if seq < self.seq_rcvd:
            #     # spurious
            #     self.rcv_spurious.append((seq,seq+l))

            # handle ack
            self.ack_rcvd = max(self.ack_rcvd, ack)
            if pd.sack != None:
                for p_ in pd.sack:
                    p = (p_[0]-self.ack_base, p_[1]-self.ack_base)
                    if p[0] > self.ack_rcvd:
                        self.snd_reordering.append(p)
                    else:
                        self.snd_spurious.append(p)

        # dup syn
        if self.tcp_state == TCP_SYN_SENT and \
                pd.dir == DIR_IN and pd.flag == 'S':
            self.dup_syn += 1

        # # before updating tcp state
        # if self.tcp_state == TCP_ESTABLISHED:
        #     # print pd
        #     print '%9.6lf, %7s, %4d' % (pd.ts-self.time_base,pd.dir,pd.leng)

        # update tcp_state
        self.tcp_state = _sm.transit(self.tcp_state, pd.dir, pd.flag)

def get_range_list(l):
    # return ', '.join([ '%d-%d' % (_[0],_[1]) for _ in l ])
    return len(l)

def parse_vse_conn(pd):
    if pd.key not in hash_table and pd.dir == DIR_IN and pd.flag == 'S':
        hash_table[pd.key] = stat_struct()
    elif pd.key not in hash_table:
        return

    stat = hash_table[pd.key]
    stat.update_state(pd)
    if stat.tcp_state == TCP_CLOSED:
        # dump the counters of this connection
        print '.'.join(pd.key.split('.')[:4])
        # print stat.seq_rcvd
        # print 'dup_syn', stat.dup_syn
        # print 'snd_retrans', get_range_list(stat.snd_retrans)
        # print 'snd_reordering', get_range_list(stat.snd_reordering)
        # print 'snd_spurious', get_range_list(stat.snd_spurious)
        # print 'rcv_reordering', get_range_list(stat.rcv_reordering)
        # print 'rcv_spurious', get_range_list(stat.rcv_spurious)

        del hash_table[pd.key]

def handle_pcap(filename):
    pcap = dpkt.pcap.Reader(open(filename))
    for ts, pkt in pcap:
        pd = get_pkt_desc(ts, pkt)
        if pd == None:
            continue

        parse_vse_conn(pd)

if __name__ == '__main__':
    if len(sys.argv) == 1:
        handle_pcap('../samples/client-data-lost/117.140.12.79.6480.pcap')
    else:
        handle_pcap(sys.argv[1])
    # for k, v in hash_table.iteritems():
    #     if len(v.in_time) != 0 and v.out_time != 0:
    #         print k, '%.3f' % (v.out_time), ' '.join([ '%.3f' % (_) for _ in v.in_time ])
