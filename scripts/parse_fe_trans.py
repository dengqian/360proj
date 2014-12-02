#!/usr/bin/python

import sys
import dpkt
import struct
import socket
import os
import subprocess

from state_machine import *
_sm = state_machine()

fe_server = '221.130.199.241'
hash_table = dict()
ip_2g = list()
ip_3g = list()
ip_wifi = list()

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
        self.rtt = 0
        self.hs_spurious = 'No Spurious Trans'
        self.trans_down = 'Trans Fail'
	self.s_cnt = 0
	self.pre_flag = 'S'
	self.pkt_cnt = 0
        self.syn_start_time = 0
        self.data_comp_time = 0
        self.http_time =  0
        self.fin_time = 0
        self.data_num = 0   

    def update_times(self, pd):
        
        #syn_start_time
        if pd.flag == 'S' and self.syn_start_time == 0:
            self.syn_start_time = pd.ts
        #data_comp_time
        if pd.dir == DIR_IN and pd.leng > 0:
            self.data_comp_time = pd.ts
        #http_time
        if pd.dir == DIR_OUT and pd.leng > 0:
            self.http_time = pd.ts
        #fin_time
        if pd.flag == 'F' and self.fin_time == 0:
            self.fin_time = pd.ts
            
    def update_state(self, pd):
        self.update_times()
        #RTT
        self.pkt_cnt += 1
        if self.pkt_cnt == 2:
            self.rtt = pd.ts
        if self.pkt_cnt == 3:
            self.rtt = pd.ts - self.rtt
        #SYN-spurious
   #     if pd.flag == 'S' and self.pre_flag == 'S':
   #         self.s_cnt += 1
   #     else:
   #         self.s_cnt = 0
   #     if self.s_cnt > 2:
   #         self.hs_spurious = 'Exist Spurious Trans'
   #     self.pre_flag = pd.flag
        #trans_down
   #     if pd.dir == DIR_OUT and pd.leng != 0:
   #         self.trans_down = 'Trans Down'  """
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
        if ip_2g.count(pd.key)>0:
            filename = 'edge.txt'
        elif ip_3g.count(pd.key)>0:
            filename = 'td.txt'
        elif ip_wifi.count(pd.key)>0:
            filename = 'wifi.txt'
        else:
            print 'key not found'
        fi = open(filename,'a')
      #  s = pd.key+'\tRTT:'+str(stat.rtt)+'\t'+stat.hs_spurious+'\t'+stat.trans_down+'\n'
        s = pd.key+'\tSYN--Last Data:'+str(stat.data_comp_time - stat.syn_start_time)+\
            '\tLast Data--HTTP:'+str(stat.http_time - stat.data_comp_time)+\
            '\tHTTP--FIN:'+str(stat.fin_time - stat.http_time)+'\t'
        if stat.data_comp_time - stat.syn_start_time <= 0:
            s += 'No Data \n'
        elif stat.http_time == 0:
            s += 'Trans Fail\n' 
        else:
            s += '\n'
        
        ip_parsed = '.'.join(pd.key.split('.')[:4])
        print ip_parsed
       # cmd = 'python qqwrq/qqwry.py -q %s' % format(ip_parsed)
      #  p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        #info = os.system('python qqwrq/qqwry.py -q %s' % format(ip_parsed))
        #print info[0:3] 
     #   fi.write(s)
        #dump the counters of this connection
        #f=open('test1.txt','a+')
        #f.write('key:',pd.key)
        #pkt_num = len(stat.in_time)
        #if pkt_num > 0:
           # f.write('stream_size:%d\tpkt_num:%d\taverage_time:%.6lf' % (stat.seq_rcvd, pkt_num, stat.in_time[pkt_num-1]/pkt_num))
        #ip_parsed = '.'.join(pd.key.split('.')[:4])
        #print ip_parsed
        #cmd = 'python qqwry.py -q %s' % format(ip_parsed)
        #p1 = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        #os.system('python qqwry.py -q %s' % format(ip_parsed))
	#f.wirte('in time: %s' % str(tcpiptests))       
        #print stat.rcv_reordering
        # print stat.seq_rcvd
        # print 'dup_syn', stat.dup_syn
        # print 'snd_retrans', get_range_list(stat.snd_retrans)
        # print 'snd_reordering', get_range_list(stat.snd_reordering)
        # print 'snd_spurious', get_range_list(stat.snd_spurious)
        # print 'rcv_reordering', get_range_list(stat.rcv_reordering)
        # print 'rcv_spurious', get_range_list(stat.rcv_spurious)

        del hash_table[pd.key]

def handle_pcap(filename):
    file = open(filename)
    pcap = dpkt.pcap.Reader(file)
   # cnt = 0
    for ts, pkt in pcap:
        pd = get_pkt_desc(ts, pkt)
        if pd == None:
            continue
       # else:
        #    print pd
        parse_vse_conn(pd)
       # cnt += 1
       # if cnt == 100000:
        #    break
def get_ip_list(filename, flag):
    f = open(filename)
    for s in f.readlines():
        ip = s.split('\t')[0]
        #print ip
        if flag == '2G':
            ip_2g.append(ip)
        elif flag == '3G':
            ip_3g.append(ip)
        else:
            ip_wifi.append(ip)
    
if __name__ == '__main__':
    if len(sys.argv) == 1:
        handle_pcap('../samples/client-data-lost/117.140.12.79.6480.pcap')
    else:
        get_ip_list('raw/edge.txt', '2G')
        get_ip_list('raw/td.txt', '3G')
        get_ip_list('raw/wifi.txt', 'WIFI')
        handle_pcap(sys.argv[1])    
        #print ip_2g[1:10]
        #print ip_3g
        #print ip_wifi
    # for k, v in hash_table.iteritems():
    #     if len(v.in_time) != 0 and v.out_time != 0:
    #         print k, '%.3f' % (v.out_time), ' '.join([ '%.3f' % (_) for _ in v.in_time ])
