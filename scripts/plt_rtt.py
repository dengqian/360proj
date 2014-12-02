#!/usr/bin/python

import matplotlib.pyplot as plt
import sys
import string

edge_rtt = list()
td_rtt = list()
wifi_rtt = list()

def plot():
    plt.legend(loc='lower right')
    plt.xlabel('x/ms')
    plt.ylabel('CDF %')
    plt.show()    

def get_rtt(filename, flag):
    f = open(filename)
    for s in f.readlines():
        rtt = s.split('\t')[1][4:]
        if flag == 'edge':
            edge_rtt.append(string.atof(rtt))
        elif flag == 'td':
            td_rtt.append(string.atof(rtt))
        else :
            wifi_rtt.append(string.atof(rtt))
def plot_all(rtt, col, lab,):
    rtt.sort()
    x = rtt
    le = 0
    y = list()
    for le in range(0, len(rtt)):
        le = float(le)
        y.append(le/len(rtt) * 100)
    print len(x),len(y)
    plt.semilogx(x, y, col, label=lab)
    plt.grid()
    plt.xlim(.001, 5)
        
if __name__ == '__main__':
    get_rtt('data/raw/edge.txt', 'edge')
    get_rtt('data/raw/td.txt', 'td')
    get_rtt('data/raw/wifi.txt', 'wifi')
    plot_all(edge_rtt, 'r-+', 'edge')
    plot_all(td_rtt, 'b-*', 'td')
    plot_all(wifi_rtt, 'y->', 'wifi')
    plot()    
