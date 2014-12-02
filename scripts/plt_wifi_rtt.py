#!/usr/bin/python

import sys
import matplotlib.pyplot as plt
import string

def plot_all(x, col, lab):
    x.sort()
    y = [ 1.*le/len(x) * 100 for le in range(len(x)) ]
    plt.semilogx(x, y, col, markeredgecolor=col[0], label=lab)
        
if __name__ == '__main__':
    edge = [ 1000.*string.atof(_) for _ in open('rtt_v3_1.txt').readlines() ]
    td = [ 1000.*string.atof(_) for _ in open('rtt_v3_2.txt').readlines() ]
    wifi = [ 1000.*string.atof(_) for _ in open('rtt_v3_3.txt').readlines() ]
    plot_all(edge, 'r-+', 't1')
    plot_all(td, 'b-*', 't2')
    plot_all(wifi, 'y-x', 't3')

    plt.xlim(1., 10000.)
    plt.xlabel('RTT (ms)')
    plt.ylabel('CDF (%)')

    plt.legend(loc='best')
    plt.grid()
    plt.show()    
    # plt.savefig('rtt2.png')
