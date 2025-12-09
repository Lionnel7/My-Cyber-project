import streamlit as st
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import streamlit_authenticator as stauth
import bcrypt

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="AI Sentinel SOC", page_icon="🛡️", layout="wide")

# ==========================================
# 1. CONFIGURATION DE L'AUTHENTIFICATION
# ==========================================

# Définition des utilisateurs
users_config = {
    'usernames': {
        'admin': {
            'name': 'Administrateur SOC',
            'password': 'admin',
            'email': 'admin@techcorp.com',
            'role': 'premium'
        },
        'visiteur': {
            'name': 'Stagiaire Démo',
            'password': '123',
            'email': 'guest@techcorp.com',
            'role': 'basic'
        }
    }
}

# --- HACHAGE MANUEL (Pour éviter les bugs de version) ---
for username, user_data in users_config['usernames'].items():
    raw_password = user_data['password']
    # Hachage sécurisé avec bcrypt
    hashed = bcrypt.hashpw(raw_password.encode(), bcrypt.gensalt()).decode()
    users_config['usernames'][username]['password'] = hashed

# Création de l'objet d'authentification
authenticator = stauth.Authenticate(
    users_config,
    'ai_sentinel_cookie',
    'cle_secrete_super_complexe',
    cookie_expiry_days=1
)

# ==========================================
# 2. MOTEUR IA (Fonctions Backend)
# ==========================================

def preprocess_data(df):
    """Prépare les données pour l'IA"""
    df_encoded = df.copy()
    le = LabelEncoder()
    # On encode uniquement les colonnes qui existent
    cols_to_encode = ['user', 'ip_address', 'status']
    for col in cols_to_encode:
        if col in df.columns:
            # Conversion en string pour éviter les bugs de type
            df_encoded[f'{col}_code'] = le.fit_transform(df[col].astype(str))
    return df_encoded

def train_and_detect(df):
    """Moteur de détection d'anomalies"""
    df_encoded = preprocess_data(df)
    
    features = ['user_code', 'ip_address_code', 'hour', 'status_code']
    available_features = [f for f in features if f in df_encoded.columns]
    
    if not available_features:
        return df
        
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    model.fit(df_encoded[available_features])
    
    df['anomaly_score'] = model.predict(df_encoded[available_features])
    return df

# ==========================================
# 3. INTERFACE UTILISATEUR (Frontend)
# ==========================================

# --- GESTION ROBUSTE DE LA CONNEXION ---
# On appelle login, mais on ne stocke pas le résultat directement pour éviter le bug 'NoneType'
authenticator.login('main')

# On vérifie l'état via la session (c'est la méthode recommandée et stable)
if st.session_state["authentication_status"] is False:
    st.error('❌ Nom d\'utilisateur ou mot de passe incorrect')
    
elif st.session_state["authentication_status"] is None:
    st.warning('🔐 Veuillez vous connecter pour accéder au SOC.')
    st.info("Comptes de test : \n- **admin** / admin (Accès total)\n- **visiteur** / 123 (Accès limité)")

elif st.session_state["authentication_status"]:
    # --- L'UTILISATEUR EST CONNECTÉ ---
    
    # Récupération des infos depuis la session
    name = st.session_state["name"]
    username = st.session_state["username"]
    
    with st.sidebar:
        st.title(f"Bienvenue, {name} 👋")
        
        # Vérification du Rôle
        try:
            user_role = users_config['usernames'][username]['role']
        except KeyError:
            user_role = 'basic'

        if user_role == 'premium':
            st.success("💎 Licence : PREMIUM")
        else:
            st.warning("⚠️ Licence : BASIC")
            
        authenticator.logout('Déconnexion', 'sidebar')
        st.divider()

    st.title("🛡️ AI Sentinel - SOC Dashboard")
    st.markdown("---")

    # UPLOAD FICHIER
    st.sidebar.header("📂 Données")
    uploaded_file = st.sidebar.file_uploader("Fichier Logs", type=["csv", "txt"])

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            
            # --- LOGIQUE D'ABONNEMENT ---
            if user_role == 'basic' and len(df) > 50:
                st.warning(f"🔒 **Mode BASIC activé :** Seules les 50 premières lignes (sur {len(df)}) seront analysées.")
                df_to_analyze = df.head(50)
            else:
                if user_role == 'premium':
                    st.success(f"🔓 **Mode PREMIUM :** Analyse complète.")
                df_to_analyze = df

            with st.expander("Voir les données brutes"):
                st.dataframe(df_to_analyze)

            # Bouton Analyse
            if st.button("🚀 LANCER L'ANALYSE IA", type="primary"):
                with st.spinner('L\'IA analyse les comportements...'):
                    
                    result_df = train_and_detect(df_to_analyze)
                    anomalies = result_df[result_df['anomaly_score'] == -1]
                    
                    st.divider()
                    
                    if not anomalies.empty:
                        st.error(f"🚨 ALERTE : {len(anomalies)} MENACES DÉTECTÉES !")
                        
                        # Affichage Rouge (Nécessite Jinja2 installé)
                        try:
                            st.dataframe(
                                anomalies.style.apply(lambda x: ['background-color: #ffcccc']*len(df.columns), axis=1),
                                use_container_width=True
                            )
                        except:
                            # Fallback si Jinja2 plante
                            st.dataframe(anomalies, use_container_width=True)
                            
                        # Détails
                        for index, row in anomalies.iterrows():
                             # Gestion d'erreur si une colonne manque dans le CSV
                             u = row.get('user', 'Inconnu')
                             ip = row.get('ip_address', 'Inconnue')
                             h = row.get('hour', '?')
                             st.warning(f"🕵️ Suspect : **{u}** | IP: **{ip}** | Heure: **{h}h**")
                    else:
                        st.success("✅ Aucune anomalie détectée.")

        except Exception as e:
            st.error(f"Erreur de lecture : {e}")
    else:
        st.info("👈 Chargez un fichier pour commencer.")
