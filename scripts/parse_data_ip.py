# -*- coding: utf-8 -*-
import sys
import dpkt

def get_ip(filename, flag):
    f = open(filename)
    for s in f.readlines():
        ip = s.split('\t')[0]
       # print ip
        ip = '.'.join(ip.split('.')[:4])
        ip += '\n'
        if flag == '2G':
            f = 'edge.txt'
        elif flag == '3G':
            f = 'td.txt'
        else :
            f = 'wifi.txt'
        fi = open(f, 'a+')
        fi.write(ip)

if __name__ == '__main__':
    get_ip('raw/edge.txt', '2G')
    get_ip('raw/td.txt', '3G')
    get_ip('raw/wifi.txt', 'WIFI')
    
