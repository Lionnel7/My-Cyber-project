import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="AI Sentinel SOC", page_icon="🛡️", layout="wide")

st.title("🛡️ AI Sentinel - SOC Dashboard")
st.markdown("""
**Bienvenue dans le centre de détection des menaces.**
Cette Intelligence Artificielle analyse vos logs pour détecter les anomalies comportementales (UEBA).
""")

# --- FONCTIONS IA (Moteur) ---

def preprocess_data(df):
    """Prépare les données pour l'IA (Transforme le texte en chiffres)"""
    df_encoded = df.copy()
    le = LabelEncoder()
    # On encode les colonnes textuelles
    for col in ['user', 'ip_address', 'status']:
        # On vérifie si la colonne existe pour éviter les erreurs
        if col in df.columns:
            df_encoded[f'{col}_code'] = le.fit_transform(df[col].astype(str))
    return df_encoded

def train_and_detect(df):
    """Entraîne l'algorithme Isolation Forest et détecte les anomalies"""
    # 1. Préparation
    df_encoded = preprocess_data(df)
    
    # Critères d'analyse (Features)
    features = ['user_code', 'ip_address_code', 'hour', 'status_code']
    
    # 2. Création du modèle (On cherche 10% d'anomalies)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    
    # 3. Entraînement sur les données chargées
    model.fit(df_encoded[features])
    
    # 4. Prédiction (-1 = Anomalie, 1 = Normal)
    df['anomaly_score'] = model.predict(df_encoded[features])
    
    return df

# --- INTERFACE UTILISATEUR (Sidebar & Main) ---

st.sidebar.header("📂 Importation des données")

# --- MODIFICATION ICI : On accepte 'csv' ET 'txt' ---
uploaded_file = st.sidebar.file_uploader(
    "Chargez votre fichier de logs", 
    type=["csv", "txt"]
)

if uploaded_file is not None:
    try:
        # Lecture du fichier
        df = pd.read_csv(uploaded_file)
        
        st.info(f"✅ Fichier chargé avec succès : {len(df)} lignes analysées.")
        
        # Affichage des données brutes
        st.subheader("📊 Aperçu des Logs en temps réel")
        st.dataframe(df, use_container_width=True)

        st.divider()

        # Bouton d'action
        if st.button("🚀 LANCER L'ANALYSE IA", type="primary"):
            with st.spinner('L\'IA analyse les comportements (Isolation Forest)...'):
                
                # Appel de la fonction de détection
                result_df = train_and_detect(df)
                
                # Filtrage : On ne garde que les anomalies (Score -1)
                anomalies = result_df[result_df['anomaly_score'] == -1]
                
                if not anomalies.empty:
                    st.error(f"🚨 ALERTE CRITIQUE : {len(anomalies)} COMPORTEMENTS SUSPECTS DÉTECTÉS !")
                    
                    # On affiche les lignes suspectes avec un fond rouge clair
                    st.dataframe(
                        anomalies.style.apply(lambda x: ['background-color: #ffcccc']*len(df.columns), axis=1),
                        use_container_width=True
                    )
                    
                    # Détails explicatifs pour chaque alerte
                    for index, row in anomalies.iterrows():
                        st.warning(
                            f"🕵️ **Suspect n°{index}** : Utilisateur **{row['user']}** "
                            f"depuis l'IP **{row['ip_address']}** à **{row['hour']}h** ({row['status']})"
                        )
                else:
                    st.success("✅ RAS : Le trafic semble légitime. Aucune anomalie statistique détectée.")

    except Exception as e:
        st.error(f"Erreur lors de la lecture du fichier : {e}")
        st.caption("Vérifiez que votre fichier est bien un CSV séparé par des virgules.")

else:
    # Message d'accueil si aucun fichier n'est chargé
    st.info("👈 Veuillez charger un fichier (CSV ou TXT) dans la barre latérale pour commencer l'investigation.")
