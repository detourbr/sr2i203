#! /usr/bin/env python
# -*- coding: utf-8 -*-

# sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.0.10 -j DRO


## TODO:
##  - vérifier que le code HTTP est 200 avant de poursuivre une attaque
##  - Prendre en compte les redirection avec le header location
##  - ATTENTION longueur payload XSS


from FormAttack import *
from http import *
from dos import *

import argparse


def parseTarget(target):
    target = target.replace('http://', '')
    target = target.replace('https://', '')

    try : host, page = target.split('/', 1)
    except : host, page = target, ''

    return host, page


if __name__ == "__main__":
    # Force Scapy to build packet at layer 3
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
    parser.add_argument("-i", "--input", help="Nom du champs à attaquer pour les attaques XSS ou les injections SQL.", action='store')
    parser.add_argument("-v", "--fieldvalue", help="Valeur par défaut d'un autre champ (optionnel) format champ=valeur. Possibilité de spécifier plusieurs champs en appelant plusieurs fois cet argument.", action='append', default=[])
    args = parser.parse_args()
    # print args

    host, page = parseTarget(args.target)

    if args.xss:
        attack = XSS(host, page, args.cookie)
        attack.run(args.input, dict([i.split('=') for i in args.fieldvalue]))

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
