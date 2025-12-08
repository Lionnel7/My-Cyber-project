import requests
import json
import argparse
import sys

print("DEBUG: Le script a bien été chargé.") # Si tu vois ça, le fichier est lu.

# --- Fonction de Recherche de Vulnérabilités ---
def check_for_vulnerabilities(service_name):
    """
    Simule une recherche de CVE.
    """
    print(f"[*] Recherche en cours pour : {service_name}...")
    
    # Normalisation : on met tout en minuscule pour faciliter la comparaison
    service_lower = service_name.lower()

    # SIMULATION : Base de données locale pour l'exercice
    # Si le service contient "apache", on sort une fausse alerte CVE
    if "apache" in service_lower:
        return [
            {
                "cve_id": "CVE-2021-41773",
                "description": "Path Traversal & RCE dans Apache 2.4.49/50 (Critique).",
                "link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
            }
        ]
    
    # Si le service contient "nginx", on ne trouve rien pour l'instant (dans notre simulation)
    elif "nginx" in service_lower:
        return []

    return []

# --- Fonction Principale ---
def main():
    parser = argparse.ArgumentParser(description="Checker de Vulnérabilités")
    parser.add_argument("service", help="Nom du service (ex: 'Apache httpd')")
    args = parser.parse_args()

    print("\n" + "="*60)
    print(f"| ANALYSE DE : {args.service}")
    print("="*60)

    # Appel de la fonction de recherche
    vulns = check_for_vulnerabilities(args.service)

    if vulns:
        print(f"\n[!] ALERTE : {len(vulns)} vulnérabilité(s) potentielle(s) trouvée(s) !")
        for v in vulns:
            print(f" - {v['cve_id']} : {v['description']}")
            print(f"   Lien : {v['link']}")
    else:
        print("\n[OK] Aucune vulnérabilité critique trouvée dans la base simulée.")

# --- POINT DE DÉMARRAGE (TRÈS IMPORTANT) ---
# Ces lignes doivent être collées tout à gauche (pas d'espace au début)
if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("Erreur : Python 3 est requis.")
        sys.exit(1)
    main()
