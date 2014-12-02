import sys

if __name__ == '__main__':
    i = '221.130.199'
    f = open(sys.argv[1])
    for s in f.readlines():
        ss = s.split('\t')[1][15:]
        ip = s.split('\t')[0]
        print s[:-1]
     #   if i in ip or ip.split('.')[0] == '10' :
      #      print ip
            
