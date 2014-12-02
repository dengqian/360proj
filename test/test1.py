import sys
import dpkt
import struct
import socket

#from state_machine import *
#_sm = state_machine()

DIR_IN = 'DIR_IN'
DIR_OUT = 'DIR_OUT'

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
        return 'ts = %.6lf, key = %s, dir = %7s, flag = %s, seq = %d, ack = %d, sack = %s, leng = %d' % \
            (self.ts, self.key, self.dir, self.flag, self.seq, self.ack, str(self.sack), self.leng)

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
                s = struct.unpack('!II', sack[:8]) #!II means two int, the same as !2I, from start num to end num lost
                sack = sack[8:]		#unpack 8bit a time
                pd.sack.append((s[0],s[1]))
            break

    pd.leng = ip.len - ip.hl*4 - tcp.off*4

    return pd

def handle_pcap(filename):
    pcap = dpkt.pcap.Reader(open(filename))
    for ts, pkt in pcap:
        pd = get_pkt_desc(ts, pkt)
        print pd
       # for line in pd.sack
        #    print line 
        if pd == None:
            continue

       # parse_vse_conn(pd)

if __name__ == '__main__':
  #  if len(sys.argv) == 1:
   #     handle_pcap('../samples/client-data-lost/117.140.12.79.6480.pcap')
    #else:
    handle_pcap(sys.argv[1])
