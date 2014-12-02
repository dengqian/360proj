import sys

def get_types(filename, type):
    f = open(filename)
    type = open(type, 'a+')
    num_list = list()
    for s in f:
        cnt = 0
        num = s.split('\t')[1][1:-2]
        # print num
        num = num.split(", ")
        # print num
        if num[0] == '1':
            type.write('t1\t' + s)
        else:
            for item in num:
                if item != '' and int(item) > 1:
                    cnt += 1
            if (cnt*1. / len(num) > 0.5):
                type.write('t2\t' + s)
            else:
                type.write('t3\t' + s)

get_types(sys.argv[1], 'edge_v4_123.txt')
