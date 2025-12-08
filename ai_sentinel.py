import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import argparse
import sys

# --- 1. CHARGEMENT DES DONNÉES (La fonction qui manquait) ---
def load_real_logs(filename):
    print(f"[*] Lecture du fichier : {filename}...")
    try:
        # Pandas lit le fichier CSV automatiquement
        df = pd.read_csv(filename)
        return df
    except FileNotFoundError:
        print(f"[-] Erreur : Le fichier '{filename}' est introuvable !")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Erreur de lecture : {e}")
        sys.exit(1)

# --- 2. PRÉPARATION DES DONNÉES (Encodage) ---
def preprocess_data(df):
    le_user = LabelEncoder()
    le_ip = LabelEncoder()
    le_status = LabelEncoder()
    
    # On crée des copies chiffrées des colonnes pour l'IA
    # L'IA ne comprend pas "admin", elle comprend "0", "1", etc.
    df['user_code'] = le_user.fit_transform(df['user'])
    df['ip_code'] = le_ip.fit_transform(df['ip_address'])
    df['status_code'] = le_status.fit_transform(df['status'])
    
    return df

# --- 3. L'INTELLIGENCE ARTIFICIELLE (Isolation Forest) ---
def train_and_detect(df):
    print("[*] Entraînement du modèle IA en cours...")
    
    # On sélectionne les critères que l'IA doit analyser
    features = ['user_code', 'ip_code', 'hour', 'status_code']
    
    # Création du modèle
    # contamination=0.1 : On estime à 10% le taux d'anomalies
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    
    # L'IA apprend ici !
    model.fit(df[features])
    
    # L'IA rend son verdict (-1 = Anomalie, 1 = Normal)
    df['anomaly_score'] = model.predict(df[features])
    
    return df

# --- MAIN (Point d'entrée) ---
def main():
    # Configuration des arguments (pour pouvoir taper le nom du fichier)
    parser = argparse.ArgumentParser(description="AI LOG SENTINEL - Détecteur d'anomalies.")
    parser.add_argument('file', type=str, help='Le chemin du fichier de logs (ex: incident_night.csv).')
    
    args = parser.parse_args()
    
    print("\n" + "="*50)
    print(f"🤖 AI LOG SENTINEL - Analyse de {args.file}")
    print("="*50)

    # 1. Charger les données (Appel de la fonction corrigée)
    df = load_real_logs(args.file)
    
    print("   -> Aperçu des données chargées :")
    print(df.head())
    print("-" * 50)

    # 2. Nettoyer/Préparer
    df_processed = preprocess_data(df)

    # 3. Détecter
    result_df = train_and_detect(df_processed)

    print("\n[2] Analyse terminée. Résultats :")
    print("-" * 50)

    # On affiche uniquement les anomalies détectées (Score -1)
    anomalies = result_df[result_df['anomaly_score'] == -1]

    if not anomalies.empty:
        print("🚨 ALERTE : COMPORTEMENTS SUSPECTS DÉTECTÉS !")
        for index, row in anomalies.iterrows():
            print(f"   [!] Utilisateur: {row['user']} | IP: {row['ip_address']} | Heure: {row['hour']}h | Statut: {row['status']}")
            print("       -> Raison : Déviation statistique forte (Isolation Forest).")
    else:
        print("✅ Tout semble normal. Aucune anomalie statistique détectée.")

if __name__ == "__main__":
    main()
