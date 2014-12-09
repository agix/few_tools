#! /usr/bin/python
import threading
from netaddr import *
import time
import sys
from scapy.all import *

def f(r):
    if r.haslayer(IP):
        i = r.getlayer(IP)
        if (i.src == DST_IP or i.dst == DST_IP) and r.haslayer(TCP):
            t = r.getlayer(TCP)
            if t.dport == DST_PORT or t.sport == DST_PORT:
                return True
            else:
                return False
        else:
            return False
    else:
        return False

class scapy_sniff (threading.Thread):
    def __init__(self, ip, port):
        threading.Thread.__init__(self)
        self.ip = ip
        self.port = port
    def run(self):
        conf.iface = 'wlp3s0'
        a = sniff(iface='wlp3s0', timeout=2)
        #a.summary()
        a = a.filter(f)
        o=False
        for r in a.res:
            if r.getlayer(TCP).flags == 17 and r.getlayer(IP).src == DST_IP:
                o = True
                break
        if o:
            print "Open"
        else:
            print "Close"

if len(sys.argv) != 3:
    print "Usage: %s <ip> <port>" % sys.argv[0]
    sys.exit()


fports=[]
ports = sys.argv[2].split(',')

for tport in ports:
    if '-' in tport:
        aports = range(int(tport.split('-')[0]),int(tport.split('-')[1])+1)
        fports += aports
    else:
        fports.append(int(tport))

ipNet = IPNetwork(sys.argv[1])
ips = list(ipNet)
fports = sorted(list(set(fports)))

for my_ip in ips:
    for my_port in fports:
        DST_IP   = str(my_ip)
        DST_PORT = my_port
        sn = scapy_sniff(DST_IP, DST_PORT)
        sn.start()
        time.sleep(1)
        sys.stdout.write("%s:%d "%(DST_IP,DST_PORT))
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((DST_IP,DST_PORT))
            s.close()
        except:
            pass
        sn.join()