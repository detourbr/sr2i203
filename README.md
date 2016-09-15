# Projet SR2I-203

## Introduction

Ce script permet de tester la présence de plusieurs failles et aussi de mettre en oeuvre différentes attaques web telles que:
* DOS de type SYN flood (mise en oeuvre)
* ShellShock (test et exploitation)
* XSS (test)
* Injection SQL (test)
* Injection de commande (test)

Le script est basé sur scapy: le DOS ainsi que les requêtes HTTP utilisées dans les attaques listées ci-dessus sont codé "from scratch" avec scapy.

## Utilisation
Pour plus de détails sur chaque paramètre, taper:

    user@debian# ./main.py --help

#### Préambule

Avant toute chose, il est nécessaire d'écrire des règles de routages via iptables. En effet les systèmes Linux les plus récents bloquent les connexions sortantes qui ne sont pas directement controlées par le noyeau. Ainsi pour que scapy fonctionne correctement, il faut entrer les règles suivantes:

    user@debian# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 137.194.X.X -j DROP
    user@debian# iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 127.0.0.1 -j DROP

La première ligne drop tous les paquets RST émis par l'interface eth0/wlan0 par défaut (attention à renseigner la bonne adresse IP). et la seconde ligne fait de même pour tous les paquets à destination de l'interface loopback (pour tester des sites hebergés sur la machine locale).

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
* `INPUT` le nom (paramètre name) du champs dans lequel tenter le XSS. S'il n'est pas spécifié, il sera tenté dans tous les champs texte.
* `name=value` le paramètre fieldvalue, pouvant être répété plusieurs fois, permet de spécifier la valeur de certains champs spécifiques dans une page.
* `target` url vers la page cible.

#### Injection SQL
Pour tester une injection SQL, la syntaxe est la suivante:

    user@debian# ./main.py --sql-injection [--input INPUT] [--cookie COOKIE] [--fieldvalue name=value] target

Avec :
* `COOKIE` le cookie à utiliser si besoin
* `INPUT` le nom (paramètre name) du champs dans lequel tenter le XSS. S'il n'est pas spécifié, il sera tenté dans tous les champs texte.
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

La gestion des requêtes étant faite par scapy, la couche TCP est entièrement controlée par la classe du SYN/ACK au FIN/ACK. Les fragments sont collectés, acquitté puis réassemblés à la fin de la requête.

La méthode getForms() permet de récupérer les formulaires et de les parser. Cela permet d'obtenir les principaux champs du formulaire afin de le remplir et le renvoyer.

Cette classe permet par ailleurs d'avoir un header customisé avec un User-Agent, un cookie ou n'importe quel autre champs avec une valeur personnalisée. Elle est utile pour les attaques ShellShock en particulier.

**A noter :** l'https n'est pas supporté.


### Classe Shellshock
*Héritée de HTTP*

Cette classe permet de tester et éventuellement d'exploiter une faille ShellShock. Le principe est assez simple. On modifie le user agent pour modifier son interpretation et lui faire executer une commande sur le shell. Tous les serveurs ayant des scripts CGI et un binaire bash non patchés (implémentation antérieure à Février 2015) sont vulnérables.

Dans ce script, le but est simplement d'afficher 'SHELLSHOCK_WORK' via la command `echo` afin de s'assurer de la présence de la faille.
Il est possible d'éxécuter d'autres commandes, mais cela dépend des paramètres de l'OS. En effet, l'utilisateur éxécutant ces commandes est www-data (en général) et n'a donc pas tous les droits. C'est pour cette raison que l'on teste la faille qu'avec un simple `echo` avant un exploitation plus avancée

## Fichier FormAttack.py

### Classe FormAttack

Cette classe s'appuie sur la classe HTTP présentée précédemment. Elle permet d'attaquer une page web en remplissant un formulaire avec un payload afin de vérifier la présence d'une faille XSS, SQLInjection ou tout autre faille basée sur l'injection d'une valeur particulière dans un formulaire.

La méthode `run()` éxécute les actions suivantes:
* recupération de la page cible via une requête GET
* sélection du formulaire ciblé par les arguments (ou choix demandé à l'utilisateur) via la méthode `selectForm()`
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

Cette classe teste plusieurs injections SQL dans le but de provoquer une erreur de la base MySQL (Oracle ou SQLite non implémentés). Si cela se produit, alors il est probable qu'aucun controle de la requête ne soit fait. On peut donc la modifier pour dérober d'autres données.

### Classe CommandInjection
*Héritée de FormAttack*

Le but est encore une fois d'injecter un morceau de code frauduleux permettant de crasher la commande qui devrait s'éxécuter en temps normal puis de faire un `echo` à la suite pour vérifier la possibilité d'enchaîner d'autres commandes.

## Fichier dos.py

Cette classe devait regrouper plusieurs attaques par déni de service. Par manque de temps, seulement une attaque a été implémentée: le TCP SYN flood.

L'attaque se déroule en 2 grandes étapes. Tout d'abord un ensemble de threads est créé, chacun ayant pour cible un intervalle de ports particulier et utilisant une fausse adresse IP (possibilité de ne pas masquer l'IP en mettant le paramètre `fake_ip` à `False` dans la fonction `tcp_syn_flood()`).
Par défaut chaque thread aura donc une adresse IP différente et une plage de 100 ports. Il est possible de modifier cela dans la méthode `createFloodPool()` de la classe DOS.

Enfin, une fois les threads créés, ils sont éxécutés en même temps lors d'une deuxième étape pour augmenter l'efficacité de l'attaque.
Il est aussi possible de répéter l'attaque en boucle jusqu'à une interruption manuelle `Ctrl + C` grâce au paramètre infinite qu'il faut mettre à `True` dans la fonction `tcp_syn_flood()`

## Fichier main.py
Ce fichier contient un parseur d'arguments puis éxécute en conséquence les attaques souhaitées sur les différentes cibles.
Il est possible d'éxécuter plusieurs attaques sur une même page.
