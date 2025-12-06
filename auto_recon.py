import argparse
import subprocess
import sys
import re

# --- Configuration des outils ---
# Nmap, le scanner de ports et de services
NMAP_COMMAND = ["nmap", "-sV", "-p-", "-T4"]
# Explication des options:
# -sV : Détection des versions de services
# -p- : Scanner tous les 65535 ports
# -T4 : Vitesse d'exécution agressive

# --- Fonction principale pour Nmap ---
def run_nmap_scan(target):
    """Lance un scan Nmap et retourne la sortie standard."""
    print(f"[*] Lancement du scan Nmap sur la cible : {target}...")

    # On assemble la commande complète
    command = NMAP_COMMAND + [target]

    try:
        # On exécute la commande et on capture le résultat
        result = subprocess.run(
            command,
            capture_output=True,  # Capture la sortie (stdout et stderr)
            text=True,            # Décode la sortie en texte (string)
            check=True            # Lève une erreur si le processus retourne un code de non-succès
        )

        # On affiche un résumé pour confirmation
        print("[+] Scan Nmap terminé avec succès.")
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"[-] ERREUR NMAP : La commande a échoué. {e}")
        # Note : e.stderr peut être None si l'erreur vient d'ailleurs, mais ici c'est ok
        print(f"Sortie d'erreur : {e.stderr}")
        return None

    except FileNotFoundError:
        print("[-] ERREUR : La commande 'nmap' n'a pas été trouvée. Assurez-vous que Nmap est installé et accessible via votre PATH.")
        return None

# --- Gestion des arguments de la ligne de commande ---
def main():
    parser = argparse.ArgumentParser(
        description="Outil de reconnaissance intégré (Nmap et Whois)."
    )
    # Ajout de l'argument cible (adresse IP ou domaine)
    parser.add_argument("target", help="Adresse IP ou nom de domaine de la cible.")

    args = parser.parse_args()

    # Exécution de la première fonction
    nmap_output = run_nmap_scan(args.target)

    if nmap_output:
        print("\n--- Sortie NMAP (Brute) ---")
        # On affiche la sortie complète pour le moment
        print(nmap_output)

        # Ici viendra l'étape suivante : l'analyse !
        # analyse_nmap_output(nmap_output)

if __name__ == "__main__":
    # Vérification que Python 3 est utilisé
    if sys.version_info[0] < 3:
        print("Ce script nécessite Python 3.")
        sys.exit(1)
    main()
