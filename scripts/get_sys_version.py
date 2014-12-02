import sys

version_dic = dict()

def get_version(filename):
    for s in open(filename):
        ip = s.split('\t')[1]
        if ip in version_dic.keys():
            print version_dic[ip][:-1] + '\t' + s[:-1]

def fil_version_dic(filename):
    for s in open(filename):
        ip = s.split(' ')[0] 
        ver = s.split(' ')[1]
        version_dic[ip] = ver

fil_version_dic("../data/other/android_version.txt")
get_version(sys.argv[1])
