import argparse
import subprocess
import sys
import re
import requests  # Nécessite: pip install requests

# --- CONFIGURATION ---
# Note : J'ai mis "-F" (Fast Scan, 100 ports) pour que tes tests soient rapides.
# Pour le vrai audit, remplace "-F" par "-p-" (Tous les ports).
NMAP_COMMAND = ["nmap", "-sV", "-F", "-T4"]

# ==========================================
# 1. FONCTIONS DE SCAN & RÉSEAU
# ==========================================

def run_nmap_scan(target):
    """Lance Nmap et récupère la sortie brute."""
    print(f"[*] Lancement du scan Nmap sur : {target}...")
    command = NMAP_COMMAND + [target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("[+] Scan Nmap terminé.")
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"[-] Erreur Nmap : {e}")
        return None
    except FileNotFoundError:
        print("[-] Erreur : Nmap n'est pas installé.")
        return None

def analyse_nmap_output(nmap_output):
    """Analyse le texte de Nmap pour extraire les ports et services."""
    services_found = []
    # Regex pour capturer : Port / Protocole / Version du service
    regex = r"(\d+)/(\w+)\s+open\s+(.*)"
    
    for line in nmap_output.splitlines():
        match = re.search(regex, line)
        if match:
            services_found.append({
                'port': match.group(1),
                'protocole': match.group(2),
                'service_version': match.group(3).strip()
            })
    return services_found

def run_whois_lookup(target):
    """Lance Whois pour les infos administratives."""
    print(f"\n[*] Recherche Whois sur : {target}...")
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, check=True)
        return result.stdout
    except Exception:
        print("[-] Whois a échoué (Probablement une IP locale ou domaine introuvable).")
        return None

def run_http_recon(target):
    """Récupère les en-têtes HTTP (Fingerprinting)."""
    print(f"\n[*] Inspection HTTP (Headers) sur : {target}...")
    url = target if target.startswith("http") else f"http://{target}"
    
    try:
        response = requests.get(url, timeout=3)
        print(f"[+] Serveur web détecté ! Code retour : {response.status_code}")
        headers = ['Server', 'X-Powered-By', 'Date']
        for h in headers:
            if h in response.headers:
                print(f"   | {h}: {response.headers[h]}")
    except Exception:
        print("[-] Pas de réponse HTTP (Le port 80/443 est peut-être fermé).")

# ==========================================
# 2. MODULE DE VULNÉRABILITÉS (SIMULATION)
# ==========================================

def check_for_vulnerabilities(service_name):
    """
    Simule une vérification CVE basée sur le nom du service.
    """
    service_lower = service_name.lower()
    
    # Simulation : Si c'est Apache, on alerte.
    if "apache" in service_lower:
        return [{
            "cve_id": "CVE-2021-41773",
            "description": "Path Traversal & RCE (Critique) sur Apache 2.4.49/50.",
            "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
        }]
    
    # Tu peux ajouter d'autres règles ici (ex: vsftpd 2.3.4)
    elif "vsftpd 2.3.4" in service_lower:
        return [{
            "cve_id": "CVE-2011-2523",
            "description": "Backdoor Command Execution (Moyenne).",
            "link": "https://www.exploit-db.com/exploits/17491"
        }]

    return []

# ==========================================
# 3. MAIN (ORCHESTRATION)
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="Outil d'Audit Automatisé (SISR Project)")
    parser.add_argument("target", help="IP ou Domaine cible")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"|  AUDIT DE SÉCURITÉ AUTOMATISÉ : {args.target}")
    print("="*60 + "\n")

    # ÉTAPE 1 : SCAN DE PORTS
    raw_nmap = run_nmap_scan(args.target)
    
    if raw_nmap:
        services = analyse_nmap_output(raw_nmap)
        
        print("\n" + "-"*60)
        print(f"| RÉSULTATS SCAN : {len(services)} services détectés")
        print("-" * 60)
        
        for svc in services:
            full_name = svc['service_version']
            print(f"| PORT: {svc['port']}/{svc['protocole']} | SERVICE: {full_name}")

        # ÉTAPE 2 : VÉRIFICATION DES VULNÉRABILITÉS (Automatique)
        if services:
            print("\n" + "#"*60)
            print("| ANALYSE DES VULNÉRABILITÉS (CVE Check)")
            print("#" * 60)
            
            alerts_count = 0
            for svc in services:
                vulns = check_for_vulnerabilities(svc['service_version'])
                if vulns:
                    alerts_count += 1
                    print(f"\n[!] ALERTE SUR LE SERVICE : {svc['service_version']}")
                    for v in vulns:
                        print(f"   --> {v['cve_id']} : {v['description']}")
                        print(f"       Ref: {v['link']}")
            
            if alerts_count == 0:
                print("\n[OK] Aucune vulnérabilité critique détectée dans la base.")

    # ÉTAPE 3 : RECONNAISSANCE HTTP
    run_http_recon(args.target)

    # ÉTAPE 4 : WHOIS
    whois_res = run_whois_lookup(args.target)
    if whois_res:
        print("\n" + "-"*60)
        print("| INFO WHOIS (Extrait)")
        print("-" * 60)
        print("\n".join(whois_res.splitlines()[:10]))
        print("...")

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        sys.exit("Erreur: Python 3 requis.")
    main()
