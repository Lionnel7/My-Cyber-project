import argparse
import subprocess
import sys
import re

# --- Configuration des outils ---
NMAP_COMMAND = ["nmap", "-sV", "-p-", "-T4"]

# --- Fonction 1 : Nmap ---
def run_nmap_scan(target):
    """Lance un scan Nmap et retourne la sortie standard."""
    print(f"[*] Lancement du scan Nmap sur la cible : {target}...")
    command = NMAP_COMMAND + [target]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        print("[+] Scan Nmap terminé avec succès.")
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"[-] ERREUR NMAP : {e}")
        return None
    except FileNotFoundError:
        print("[-] ERREUR : La commande 'nmap' est introuvable.")
        return None

# --- Fonction 2 : Whois ---
def run_whois_lookup(target):
    """Lance une recherche Whois sur la cible."""
    print(f"\n[*] Lancement de la recherche Whois sur la cible : {target}...")
    WHOIS_COMMAND = ["whois", target]

    try:
        result = subprocess.run(
            WHOIS_COMMAND,
            capture_output=True,
            text=True,
            check=True
        )
        print("[+] Recherche Whois terminée avec succès.")
        return result.stdout

    except subprocess.CalledProcessError:
        print(f"[-] AVERTISSEMENT WHOIS : La commande a échoué (cible non trouvée ou pas un domaine).")
        return None
    except FileNotFoundError:
        print("[-] ERREUR : La commande 'whois' n'a pas été trouvée. Installez-la (sudo apt install whois).")
        return None

# --- Fonction 3 : Analyse (Parsing) ---
# J'ai ajouté cette fonction car ton nouveau 'main' l'appelle !
def analyse_nmap_output(nmap_output):
    """Cherche les ports ouverts dans la sortie texte de Nmap."""
    services_found = []
    
    # Regex pour trouver les lignes comme : "80/tcp open http Apache..."
    # (\d+) = Le port
    # (\w+) = Le protocole (tcp)
    # open = Le statut
    # (.*) = Le reste (service et version)
    regex_pattern = r"(\d+)/(\w+)\s+open\s+(.*)"

    for line in nmap_output.splitlines():
        match = re.search(regex_pattern, line)
        if match:
            service_info = {
                'port': match.group(1),
                'protocole': match.group(2),
                'service_version': match.group(3).strip()
            }
            services_found.append(service_info)
            
    return services_found

# --- Fonction Principale (Orchestration) ---
def main():
    # 1. Gestion des arguments
    parser = argparse.ArgumentParser(
        description="Outil d'automatisation de la reconnaissance (Nmap, Whois, etc.)."
    )
    parser.add_argument("target", help="Adresse IP ou nom de domaine de la cible.")
    args = parser.parse_args()

    print("\n" + "="*70)
    print(f"| DÉBUT DE LA RECONNAISSANCE AUTOMATISÉE SUR : {args.target}")
    print("="*70)

    # 2. Exécution du Scan Nmap
    nmap_output = run_nmap_scan(args.target)

    if nmap_output:
        # Appel de la fonction d'analyse (que j'ai ajoutée plus haut)
        services = analyse_nmap_output(nmap_output)

        print("\n" + "-"*70)
        print("| RÉSULTATS D'ANALYSE NMAP (PORTS OUVERTS)")
        print("-"*70)

        if services:
            for svc in services:
                print(f"| PORT: {svc['port']}/{svc['protocole']} | SERVICE/VERSION: {svc['service_version']}")
        else:
            print("| Aucun service ouvert significatif trouvé (ou format non reconnu).")

    # 3. Exécution de Whois
    whois_output = run_whois_lookup(args.target)

    if whois_output:
        print("\n" + "-"*70)
        print("| RÉSULTATS WHOIS (Sortie Brute - 20 premières lignes)")
        print("-"*70)
        
        # On affiche seulement le début pour ne pas polluer l'écran
        print("\n".join(whois_output.splitlines()[:20]))
        print("\n[... suite tronquée ...]")

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("Ce script nécessite Python 3.")
        sys.exit(1)
    main()
