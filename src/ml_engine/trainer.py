import pandas as pd
import numpy as np
import re
import scipy.sparse as sp
import joblib
import os

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier


FEATURE_NAMES = [
    "subject_length", "body_length", "word_count",
    "urgency_score", "caps_ratio", "has_url",
    "exclamation_count", "question_count", "html_tags_count",
    "url_count", "url_length_avg", "has_ip_in_url",
    "url_obfuscated", "subdomain_count", "suspicious_url_keywords",
    "url_has_https", "url_tld_suspect",
    "sender_domain_length", "sender_has_numbers",
    "sender_domain_suspicious", "sender_tld_suspect",
    "display_name_mismatch",
]


def nettoyer_texte(texte):
    texte = str(texte).lower()
    texte = re.sub(r'http\S+', ' URL ', texte)
    texte = re.sub(r'\S+@\S+', ' EMAIL ', texte)
    texte = re.sub(r'[^a-zA-Z0-9\s]', ' ', texte)
    texte = re.sub(r'\s+', ' ', texte).strip()
    return texte


def train(csv_path: str, output_dir: str = "modeles_sauvegardes"):
    """
    Entraîne tous les modèles et sauvegarde les fichiers .pkl

    Paramètres :
      csv_path   → chemin vers CEAS_08.csv
      output_dir → dossier de sauvegarde des modèles
    """

    # ── 1. Chargement et nettoyage ──────────────────────────────
    print("⏳ Chargement du dataset...")
    df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
    df = df.copy()
    df['subject']  = df['subject'].fillna('')
    df['receiver'] = df['receiver'].fillna('unknown')
    df = df.drop_duplicates(subset=['subject', 'body'])
    print(f"✅ {len(df)} emails chargés")

    # ── 2. Nettoyage texte ───────────────────────────────────────
    df['subject_clean'] = df['subject'].apply(nettoyer_texte)
    df['body_clean']    = df['body'].apply(nettoyer_texte)

    # ── 3. Features numériques ───────────────────────────────────
    mots_urgents = [
        'urgent','verify','account','suspended','click',
        'confirm','password','bank','winner','free',
        'congratulations','limited','expire','immediately'
    ]
    tlds_suspects = ['.ru','.tk','.ml','.ga','.cf','.gq','.xyz','.top','.pw','.cc']

    def extraire_urls(texte):
        return re.findall(r'http[s]?://[^\s<>"{}|\\^`\[\]]+', str(texte))

    df['urls_extraites']         = df['body'].apply(extraire_urls)
    df['subject_length']         = df['subject'].apply(lambda x: len(str(x)))
    df['body_length']            = df['body'].apply(lambda x: len(str(x)))
    df['word_count']             = df['body_clean'].apply(lambda x: len(str(x).split()))
    df['urgency_score']          = df['body_clean'].apply(lambda x: sum(1 for m in mots_urgents if m in str(x)))
    df['has_url']                = df['body_clean'].apply(lambda x: 1 if 'url' in str(x) else 0)
    df['caps_ratio']             = df['subject'].apply(lambda x: sum(1 for c in str(x) if c.isupper()) / max(len(str(x)),1))
    df['exclamation_count']      = df['body'].apply(lambda x: str(x).count('!'))
    df['question_count']         = df['body'].apply(lambda x: str(x).count('?'))
    df['html_tags_count']        = df['body'].apply(lambda x: len(re.findall(r'<[^>]+>', str(x))))
    df['url_count']              = df['urls_extraites'].apply(len)
    df['url_length_avg']         = df['urls_extraites'].apply(lambda u: round(sum(len(x) for x in u)/len(u),2) if u else 0)
    df['has_ip_in_url']          = df['urls_extraites'].apply(lambda u: 1 if any(re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}',x) for x in u) else 0)
    df['url_obfuscated']         = df['urls_extraites'].apply(lambda u: 1 if any(s in x for x in u for s in ['@','//','%20','0x']) else 0)
    df['subdomain_count']        = df['urls_extraites'].apply(lambda u: max((len(re.sub(r'https?://','',x).split('/')[0].split('.'))-2 for x in u), default=0))
    df['suspicious_url_keywords']= df['urls_extraites'].apply(lambda u: sum(1 for x in u for k in ['login','verify','secure','account','confirm'] if k in x.lower()))
    df['url_has_https']          = df['urls_extraites'].apply(lambda u: 1 if any(x.startswith('https') for x in u) else 0)
    df['url_tld_suspect']        = df['urls_extraites'].apply(lambda u: 1 if any(t in x.lower() for x in u for t in tlds_suspects) else 0)

    def extraire_domaine(sender):
        m = re.search(r'@([\w.\-]+)', str(sender))
        return m.group(1).lower() if m else 'unknown'

    df['sender_domain']              = df['sender'].apply(extraire_domaine)
    df['sender_domain_length']       = df['sender_domain'].apply(len)
    df['sender_has_numbers']         = df['sender_domain'].apply(lambda d: 1 if re.search(r'\d', d) else 0)
    df['sender_domain_suspicious']   = df['sender_domain'].apply(lambda d: 1 if any(w in d for w in ['secure','verify','login','account','update']) else 0)
    df['sender_tld_suspect']         = df['sender_domain'].apply(lambda d: 1 if any(d.endswith(t) for t in tlds_suspects) else 0)

    def mismatch(sender):
        m = re.search(r'^([^<]+)<', str(sender))
        nom = m.group(1).strip().lower() if m else ''
        dom = extraire_domaine(sender)
        for marque in ['paypal','google','amazon','apple','microsoft','facebook','netflix']:
            if marque in nom and marque not in dom:
                return 1
        return 0

    df['display_name_mismatch'] = df['sender'].apply(mismatch)

    # ── 4. TF-IDF + Scaler ──────────────────────────────────────
    df['text_combined'] = df['subject_clean'] + ' ' + df['body_clean']

    tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1,2),
                            stop_words='english', min_df=2, sublinear_tf=True)
    X_tfidf = tfidf.fit_transform(df['text_combined'])

    X_num = df[FEATURE_NAMES].values
    scaler = StandardScaler()
    X_num_scaled = scaler.fit_transform(X_num)

    X_final = sp.hstack([sp.csr_matrix(X_num_scaled), X_tfidf])
    y = df['label'].values

    X_train, X_test, y_train, y_test = train_test_split(
        X_final, y, test_size=0.2, random_state=42, stratify=y)

    # ── 5. Entraînement des modèles ──────────────────────────────
    print("\n⏳ Entraînement Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, n_jobs=-1,
                                random_state=42, class_weight='balanced')
    rf.fit(X_train, y_train)
    print(f"✅ RF : {accuracy_score(y_test, rf.predict(X_test))*100:.2f}%")

    print("⏳ Entraînement XGBoost...")
    xgb = XGBClassifier(n_estimators=100, learning_rate=0.1, max_depth=6,
                        n_jobs=-1, random_state=42, eval_metric='logloss', verbosity=0)
    xgb.fit(X_train, y_train)
    print(f"✅ XGB : {accuracy_score(y_test, xgb.predict(X_test))*100:.2f}%")

    print("⏳ Entraînement SVM...")
    svm = LinearSVC(C=1.0, random_state=42, max_iter=2000, class_weight='balanced')
    svm.fit(X_train, y_train)
    print(f"✅ SVM : {accuracy_score(y_test, svm.predict(X_test))*100:.2f}%")

    # ── 6. Sauvegarde ────────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)
    joblib.dump(rf,     f"{output_dir}/random_forest.pkl")
    joblib.dump(xgb,    f"{output_dir}/xgboost.pkl")
    joblib.dump(svm,    f"{output_dir}/svm.pkl")
    joblib.dump(tfidf,  f"{output_dir}/tfidf_vectorizer.pkl")
    joblib.dump(scaler, f"{output_dir}/scaler.pkl")
    joblib.dump(FEATURE_NAMES, f"{output_dir}/liste_features.pkl")
    print(f"\n✅ Tous les modèles sauvegardés dans {output_dir}/")


if __name__ == "__main__":
    train("CEAS_08.csv")