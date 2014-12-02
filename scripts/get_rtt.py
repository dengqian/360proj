import sys

rtt_dic = dict()
def get_rtt(filename):
    f = open(filename)
    for s in f.readlines():
        ip = s.split('\t')[0]
        rtt = s.split('\t')[1][4:]
        rtt_dic[ip] = rtt

def get_ip(filename):
    f = open(filename)
    for s in f.readlines():
        ip = s.split('\t')[0]
        print ip+'\t'+rtt_dic[ip]
if __name__ == '__main__':
    get_rtt("edge.txt")
    get_rtt("td.txt")
    get_rtt("wifi.txt")
    get_ip(sys.argv[1])
        
