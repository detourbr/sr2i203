# Projet SR2I-203

## Introduction

Ce script permet de tester la présence de plusieurs failles mais aussi de mettre en oeuvre différentes attaques web telles que:
* DOS de type SYN flood (mise en oeuvre)
* ShellShock (test et exploitation)
* XSS (test)
* Injection SQL (test)
* Injection de commande (test)

Le script est basé sur scapy: le DOS ainsi que les requêtes HTTP utilisées dans les attaques listées ci-dessus sont codé "from scratch" avec scapy.

## Utilisation
Pour plus de détails sur chaque paramètre, taper:

    user@debian# ./main.py --help

#### DOS - SYN flood
Pour lancer une attaque SYN flood, la syntaxe est la suivante:

    user@debian# ./main.py --tcp-syn-flood [-p port] target

Avec `port` le port à attaquer et `target` la machine cible.

#### ShellShock
Pour tester une attaque ShellShock, la syntaxe est la suivante:

    user@debian# ./main.py --shellshock [--cookie COOKIE] target

Avec `COOKIE` le cookie à utiliser si besoin et `target` la page cible (script cgi).

#### XSS
Pour tester une attaque XSS, la syntaxe est la suivante:

    user@debian# ./main.py --xss [--input INPUT] [--cookie COOKIE] [--fieldvalue name=value] target

Avec :
* `COOKIE` le cookie à utiliser si besoin
* `INPUT` le nom (paramètre name) du champs dans lequel tenter le XSS. S'il n'est pas spécifié il sera tenté dans tous les champs texte.
* `name=value` le paramètre fieldvalue, pouvant être répété plusieurs fois, permet de spécifier la valeur de certains champs spécifiques dans une page.
* `target` url vers la page cible.

#### Injection SQL
Pour tester une injection SQL, la syntaxe est la suivante:

    user@debian# ./main.py --sql-injection [--input INPUT] [--cookie COOKIE] [--fieldvalue name=value] target

Avec :
* `COOKIE` le cookie à utiliser si besoin
* `INPUT` le nom (paramètre name) du champs dans lequel tenter le XSS. S'il n'est pas spécifié il sera tenté dans tous les champs texte.
* `name=value` le paramètre fieldvalue, pouvant être répété plusieurs fois, permet de spécifier la valeur de certains champs spécifiques dans une page.
* `target` url vers la page cible.

#### Injection de commande
Pour tester une injection de commande, la syntaxe est la suivante:

    user@debian# ./main.py --command-injection [--input INPUT] [--cookie COOKIE] [--fieldvalue name=value] target

Avec :
* `COOKIE` le cookie à utiliser si besoin
* `INPUT` le nom (paramètre name) du champs dans lequel tenter le XSS. S'il n'est pas spécifié il sera tenté dans tous les champs texte.
* `name=value` le paramètre fieldvalue, pouvant être répété plusieurs fois, permet de spécifier la valeur de certains champs spécifiques dans une page.
* `target` url vers la page cible .

## Fichier http.py

### Classe HTTP
Cette classe permet d'envoyer et de recevoir des requêtes HTTP en s'appuyant sur scapy.
Elle gère tout particulièrement les requêtes GET et POST.

La gestion des requêtes étant gérées par scapy, la couche TCP est entièrement controlée par la classe du SYN/ACK au FIN/ACK. Les fragments sont collectés, acquitté puis réassemblés à la fin de la requête.

La méthode getForms() permet de récupérer les formulaires et de les parser. Cela permet d'obtenir les principaux champs du formulaire afin de le remplir et le renvoyer.

Cette classe permet par ailleurs d'avoir un header customisé avec un User-Agent, un cookie ou n'importe quel autre champs avec une valeure personnalisée. Utile pour les attaques ShellShock en particulier.

**A noter :** l'https n'est pas supporté.


### Classe Shellshock
*Héritée de HTTP*

Cette classe permet de tester et éventuellement d'exploiter une faille ShellShock. Le principe est assez simple. On modifie le user agent pour modifier sont interpretation et lui faire executer une commande sur le shell. Tous les serveurs ayant des scripts CGI et un binaire bash non patchés (implémentation antérieure à Février 2015) sont vulnérables.

Dans ce script, le but est simplement d'afficher 'SHELLSHOCK_WORK' via la command `echo` afin de s'assurer de la présence de la faille.
Il est possible d'éxécuter d'autres commandes, mais cela dépend des paramètres de l'OS. En effet, l'utilisateur éxécutant ces commandes est www-data (en général) et n'a donc pas tous les droits. C'est pour cette raison que l'on teste la faille qu'avec un simple `echo` avant un exploitation plus avancée

## Fichier FormAttack.py

### Classe FormAttack

Cette classe s'appuie sur la classe HTTP présentée précédemment. Elle permet d'attaquer une page web en remplissant un formulaire avec un payload afin de vérifier la présence d'une faille XSS, SQLInjection ou tout autre faille basée sur l'injection d'une valeure particulière dans un formulaire.

La méthode `run()` éxécute les actions suivantes:
* recupération de la page cible via une requête GET
* séléction du formulaire ciblé par les arguments (ou choix demandé à l'utilisateur) via la méthode `selectForm()`
* remplissage du formulaire précédemment séléctionné en y injectant la charge (payload) via la méthode `fillForm()`
* formattage et renvoie du formulaire en GET ou en POST

### Classe XSS
*Héritée de FormAttack*

Cette classe injecte le code suivant dans un formulaire:
```
    <a onmouseover="alert('...')">x</a>
```
Pour vérifier que la faille est présente, il suffit de vérifier que ce code est bien présent, tel quel, sans caractère d'échappement.

### Classe SQLInjection
*Héritée de FormAttack*

Cette classe teste plusieurs injections SQL dans le but de provoquer une erreur de la base MySQL (Oracle ou SQLite non implémentés). Si cela est se produit, alors il est probable qu'aucun controle de la requête ne soit fait. On peut donc la modifier pour dérober d'autre données.

### Classe CommandInjection
*Héritée de FormAttack*

Le but est encore une fois d'injecter un morceau de code frauduleux permettant de crasher la commande qui devrait s'éxécuter en temps normal puis de faire un `echo` à la suite pour vérifier la possibilité d'enchaîner d'autres commandes.

## Fichier dos.py

Cette classe devait regrouper plusieurs attaque par déni de service. Par manque de temps, seulement une à été implémentée: le TCP SYN flood.

## Fichier main.py
