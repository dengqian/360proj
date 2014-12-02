import sys
import string

pro_dic = dict()

def get_pro(filename):
    f = open(filename)
    for s in f.readlines():
        ip = s.split(' ')[0]
        pro = s.split(' ')[1][0:6]
        #print pro
        pro_dic[ip] = pro
        
class rtt_info:
    def __init__(self):
        self.td_dic = dict()
        self.edge_dic = dict()
        self.wifi_dic = dict()
    def get_rtt_list(self, filename, flag):
        f = open(filename)
        for s in f.readlines():
            ip = s.split('\t')[0]
            ip = '.'.join(ip.split('.')[:4])
            rtt = s.split('\t')[1][4:]
         #   print rtt
            pro = pro_dic[ip]
            if flag == 'edge':
                dic = self.edge_dic
            elif flag == 'td':
                dic = self.td_dic
            else:
                dic = self.wifi_dic
            if pro in dic.keys():
                dic[pro].append(rtt)
            else:
                dic[pro] = list()
                dic[pro].append(rtt)
    def get_avr_rtt(self):
        for key, val in self.edge_dic.items():
            rt = 0
            for it in val:
                rt += string.atof(it)
            leng = len(val)
            avr_rtt = rt / leng
            self.edge_dic[key].append(avr_rtt)
        for key, val in self.td_dic.items():
            rt = 0
            for it in val:
                rt += string.atof(it)
            leng = len(val)
            avr_rtt = rt / leng
            self.td_dic[key].append(avr_rtt)
        for key, val in self.wifi_dic.items():
            rt = 0
            for it in val:
                rt += string.atof(it)
            leng = len(val)
            avr_rtt = rt / leng
            self.wifi_dic[key].append(avr_rtt)
    
def get_rtt(filename, flag):
    rtt = rtt_info()
    rtt.get_rtt_list(filename, flag)
    rtt.get_avr_rtt()
    if flag == 'edge':
        _dic = rtt.edge_dic
    elif flag == 'td':
        _dic = rtt.td_dic
    else:
        _dic = rtt.wifi_dic
        
    print _dic['\xe6\xb1\x9f\xe8\xa5\xbf']
    for key, val in _dic.items():
        print key+'\t'+str(val[len(val)-1])
        
if __name__ == '__main__':
    get_pro('data/edge_info.txt')
    get_pro('data/td_info.txt')
    get_pro('data/wifi_info.txt')
    get_rtt('data/raw/edge.txt', 'edge')
 #   get_rtt('data/raw/td.txt', 'td')
 #   get_rtt('data/raw/wifi.txt', 'wifi')
