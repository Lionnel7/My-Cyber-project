import argparse
import subprocess
import sys
import re
import requests
import os

# --- CONFIGURATION ---
# Mode Rapide (-F) activé pour les tests. Mets "-p-" pour un vrai audit.
NMAP_COMMAND = ["nmap", "-sV", "-F", "-T4"]

# ==========================================
# 1. FONCTIONS TECHNIQUES
# ==========================================

def run_nmap_scan(target):
    """Lance Nmap sur une cible donnée."""
    print(f"[*] Scan Nmap en cours sur : {target}...")
    command = NMAP_COMMAND + [target]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception as e:
        print(f"[-] Erreur Nmap : {e}")
        return None

def analyse_nmap_output(nmap_output):
    """Extrait les services du résultat Nmap."""
    services_found = []
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

def run_http_recon(target):
    """Récupère les headers HTTP."""
    print(f"[*] Inspection HTTP sur : {target}...")
    url = target if target.startswith("http") else f"http://{target}"
    try:
        response = requests.get(url, timeout=3)
        print(f"[+] Serveur web détecté (Code {response.status_code})")
        headers = ['Server', 'X-Powered-By', 'Date']
        for h in headers:
            if h in response.headers:
                print(f"   | {h}: {response.headers[h]}")
    except Exception:
        print("[-] Pas de réponse HTTP.")

def run_whois_lookup(target):
    """Lance Whois."""
    try:
        # Whois ne marche pas bien sur les IP locales, on ignore les erreurs silencieusement
        result = subprocess.run(["whois", target], capture_output=True, text=True, check=False)
        return result.stdout
    except Exception:
        return None

def check_for_vulnerabilities(service_name):
    """Simulateur de scanner de vulnérabilités."""
    service_lower = service_name.lower()
    if "apache" in service_lower:
        return [{"cve_id": "CVE-2021-41773", "description": "Path Traversal & RCE (Critique).", "link": "NVD"}]
    elif "vsftpd 2.3.4" in service_lower:
        return [{"cve_id": "CVE-2011-2523", "description": "Backdoor Command Execution.", "link": "ExploitDB"}]
    return []

# ==========================================
# 2. LOGIQUE D'AUDIT (Pour une seule cible)
# ==========================================

def audit_target(target):
    """Exécute toute la chaîne d'audit sur UNE cible."""
    print("\n" + "█"*60)
    print(f"█  CIBLE : {target}")
    print("█" + "█"*60 + "\n")

    # Étape 1 : Nmap
    raw_nmap = run_nmap_scan(target)
    
    if raw_nmap:
        services = analyse_nmap_output(raw_nmap)
        print(f"[+] {len(services)} services ouverts détectés.")
        
        for svc in services:
            print(f"   > PORT {svc['port']}/{svc['protocole']} : {svc['service_version']}")
            
            # Étape 2 : Vulnérabilités
            vulns = check_for_vulnerabilities(svc['service_version'])
            if vulns:
                print(f"     [!!!] ALERTE SÉCURITÉ : {vulns[0]['cve_id']} ({vulns[0]['description']})")

    # Étape 3 : HTTP
    run_http_recon(target)

    # Étape 4 : Whois (Rapide)
    whois_res = run_whois_lookup(target)
    if whois_res:
        print("[+] Données Whois récupérées.")

# ==========================================
# 3. MAIN (Gestion Multi-Cibles)
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="AutoRecon V2 - Audit Multi-Cibles")
    parser.add_argument("input", help="IP unique OU Fichier contenant une liste d'IPs")
    args = parser.parse_args()

    targets_list = []

    # Vérification : Est-ce un fichier ?
    if os.path.isfile(args.input):
        print(f"[i] Mode FICHIER activé. Lecture de {args.input}...")
        try:
            with open(args.input, "r") as f:
                # On nettoie les lignes (enlève les espaces et sauts de ligne)
                targets_list = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[-] Impossible de lire le fichier : {e}")
            sys.exit(1)
    else:
        # Sinon c'est une IP unique
        print("[i] Mode CIBLE UNIQUE activé.")
        targets_list = [args.input]

    # Boucle de traitement
    print(f"[i] Démarrage de l'audit sur {len(targets_list)} cible(s)...")
    
    for i, target in enumerate(targets_list, 1):
        print(f"\n--- Traitement {i}/{len(targets_list)} ---")
        audit_target(target)

    print("\n" + "="*60)
    print("✅ AUDIT TERMINÉ POUR TOUTES LES CIBLES")
    print("="*60)

if __name__ == "__main__":
    if sys.version_info[0] < 3: sys.exit("Python 3 requis.")
    main()
