#!/usr/bin/python

DIR_IN = 'DIR_IN'
DIR_OUT = 'DIR_OUT'

__ts = [ 'TCP_LISTEN', 'TCP_SYN_RCVD', 'TCP_SYN_SENT', \
        'TCP_ESTABLISHED', 'TCP_FIN_SENT', 'TCP_FIN_1', \
        'TCP_FIN_RCVD', 'TCP_FIN_2', 'TCP_CLOSED' ]
for s in __ts:
    exec("%s = '%s'" % (s, s))

class state_machine:
    def __init__(self):
        # cur_state + dir + flag -> nxt_state
        __s = list()
        ## 3-way handshake
        __s.append((TCP_LISTEN, DIR_IN, 'S', TCP_SYN_RCVD))
        __s.append((TCP_SYN_RCVD, DIR_OUT, 'S', TCP_SYN_SENT))
        __s.append((TCP_SYN_SENT, DIR_IN, 'S', TCP_SYN_RCVD))
        __s.append((TCP_SYN_SENT, DIR_IN, 'A', TCP_ESTABLISHED))
        
        # during transmission
        __s.append((TCP_ESTABLISHED, DIR_IN, 'A', TCP_ESTABLISHED))
        __s.append((TCP_ESTABLISHED, DIR_OUT, 'A', TCP_ESTABLISHED))
        
        # end of connection
        __s.append((TCP_ESTABLISHED, DIR_OUT, 'F', TCP_CLOSED))
        __s.append((TCP_ESTABLISHED, DIR_IN, 'F', TCP_CLOSED))
        __s.append((TCP_ESTABLISHED, DIR_IN, 'R', TCP_CLOSED))

        # __s.append((TCP_ESTABLISHED, DIR_OUT, 'F', TCP_SYN_SENT))
        # __s.append((TCP_FIN_SENT, DIR_IN, 'A', TCP_FIN_1))
        # __s.append((TCP_FIN_1, DIR_IN, 'A', TCP_FIN_1))
        # __s.append((TCP_FIN_1, DIR_IN, 'F', TCP_FIN_RCVD))
        # __s.append((TCP_FIN_RCVD, DIR_OUT, 'A', TCP_CLOSED))

        # __s.append((TCP_ESTABLISHED, DIR_IN, 'R', TCP_CLOSED))
        # __s.append((TCP_FIN_SENT, DIR_IN, 'R', TCP_CLOSED))
        # __s.append((TCP_FIN_1, DIR_IN, 'R', TCP_CLOSED))

        self._sm = dict()
        for s in __s:
            if s[0] not in self._sm:
                self._sm[s[0]] = dict()
            self._sm[s[0]][(s[1],s[2])] = s[3]

    def transit(self, cur, dir, flag):
        try:
            return self._sm[cur][(dir,flag)]
        except KeyError:
            # log error
            return cur
