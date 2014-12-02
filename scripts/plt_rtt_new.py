#!/usr/bin/python

import sys
import matplotlib.pyplot as plt
import string

def plot_all(x, col, lab):
    x.sort()
    y = [ 1.*le/len(x) * 100 for le in range(len(x)) ]
    plt.semilogx(x, y, col, markeredgecolor=col[0], label=lab)
        
if __name__ == '__main__':
    edge = [ 1000.*string.atof(_) for _ in open('e.txt').readlines() ]
    td = [ 1000.*string.atof(_) for _ in open('t.txt').readlines() ]
    wifi = [ 1000.*string.atof(_) for _ in open('w.txt').readlines() ]
    plot_all(edge, 'r-+', 'edge')
    plot_all(td, 'b-*', 'td')
    plot_all(wifi, 'y-x', 'wifi')

    plt.xlim(1., 20000.)
    plt.xlabel('UPLOAD TIME (ms)')
    plt.ylabel('CDF (%)')

    plt.legend(loc='upper left')
    plt.grid()
    # plt.show()    
    plt.savefig('rtt1.png')