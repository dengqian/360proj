import sys

pro_dic = dict()

def get_pro(filename):
    for s in open(filename):
        ip = s.split('\t')[1]
        ip = '.'.join(ip.split('.')[:4])
        if ip in pro_dic.keys():
            print pro_dic[ip][:-1] + '\t' + s[:-1]

def fil_pro_dic(filename):
    for s in open(filename):
        ip = s.split(' ')[0] 
        pro = ' '.join(s.split(' ')[1:])
        pro_dic[ip] = pro

fil_pro_dic("../data/raw/pro_info/pro_info.txt")
#print pro_dic
get_pro(sys.argv[1])
