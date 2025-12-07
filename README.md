# My-Cyber-project
# 🛡️ AutoRecon - Outil d'Audit de Sécurité Automatisé

> **Projet BTS SIO (Option SISR)** > *Automatisation de la phase de reconnaissance et de détection de vulnérabilités.*

## 📋 Présentation

**AutoRecon** est un outil CLI (Ligne de Commande) développé en **Python 3**. Il permet aux administrateurs systèmes et auditeurs de cybersécurité d'automatiser les tâches répétitives lors d'un audit de premier niveau.

Au lieu d'exécuter manuellement plusieurs outils disparates, ce script orchestre l'ensemble du processus en une seule commande, corrèle les résultats et fournit un rapport structuré.

---

## 🚀 Fonctionnalités Clés

L'outil exécute automatiquement les 4 phases suivantes :

### 1. 🔍 Cartographie Réseau (Nmap)
* Scan des ports TCP (détection des services ouverts).
* **Fingerprinting :** Identification précise des versions de services (ex: *Apache 2.4.52*).
* Utilisation de **Regex** (Expressions Régulières) pour analyser et extraire proprement les données brutes.

### 2. 🚨 Analyse de Vulnérabilités (Simulation)
* Module de **Vulnerability Assessment** intégré.
* Compare les versions de services détectées avec une base de données interne de **CVE** (Common Vulnerabilities and Exposures).
* *Note : Ce module fonctionne en mode simulation pour démontrer la logique de détection (ex: réaction aux mots-clés "Apache" ou "vsftpd").*

### 3. 🌐 Inspection HTTP (Web Recon)
* Analyse des en-têtes HTTP (`Headers`) pour identifier les technologies web.
* Confirmation de la présence de serveurs web via le code retour (200 OK).
* Détection des fuites d'informations serveur (`Server`, `X-Powered-By`).

### 4. 📝 Informations Administratives (Whois)
* Récupération des informations sur le propriétaire de l'IP ou du domaine.
* Identification du Registrar et des serveurs de noms.

---

## 🛠️ Prérequis & Installation

### Système
* Linux (Ubuntu, Debian, Kali ou WSL).
* Python 3.x installé.

### Dépendances Système
L'outil pilote des programmes Linux natifs. Ils doivent être installés :
```bash
sudo apt update
sudo apt install nmap whois python3-pip -y

Librairies Python
Installation des modules tiers nécessaires (notamment requests) :
Bash
pip3 install requests

💻 Utilisation
Lancer le script avec les droits utilisateur (ou sudo si besoin de scans Nmap avancés) en ciblant une IP ou un nom de domaine.

Scanner une IP (Infrastructure) :

Bash

python3 auto_recon.py 192.168.1.25
Scanner un Domaine (Web) :

Bash

python3 auto_recon.py google.com
📊 Exemple de Résultat
Plaintext

============================================================
|  AUDIT DE SÉCURITÉ AUTOMATISÉ : 127.0.0.1
============================================================

[*] Lancement du scan Nmap sur : 127.0.0.1...
[+] Scan Nmap terminé.

------------------------------------------------------------
| RÉSULTATS SCAN : 1 services détectés
------------------------------------------------------------
| PORT: 80/tcp | SERVICE: http    Apache httpd 2.4.52 ((Ubuntu))

############################################################
| ANALYSE DES VULNÉRABILITÉS (CVE Check)
############################################################

[!] ALERTE SUR LE SERVICE : http    Apache httpd 2.4.52 ((Ubuntu))
   --> CVE-2021-41773 : Path Traversal & RCE (Critique).
       Ref: [https://nvd.nist.gov/vuln/detail/CVE-2021-41773](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)
🎓 Compétences BTS SIO Validées
Ce projet permet de valider les compétences suivantes du bloc SISR :

✅ Gérer le patrimoine informatique : Recensement des services et versions.

✅ Protéger les services et les données : Identification des vulnérabilités potentielles.

✅ Participer au développement d'une application : Scripting, algorithmique, utilisation d'API et de sous-processus.
