import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

import pandas as pd
import numpy as np
import joblib
import scipy.sparse as sp
import re
import time
import json
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report
)

MODELS_DIR = Path("modeles_sauvegardes")
CSV_PATH   = "CEAS_08.csv"

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

TLDS_SUSPECTS = ['.ru','.tk','.ml','.ga','.cf','.gq','.xyz','.top','.pw','.cc']
MOTS_URGENTS  = [
    'urgent','verify','account','suspended','click',
    'confirm','password','bank','winner','free',
    'congratulations','limited','expire','immediately'
]


# ══════════════════════════════════════════════════════════════════
# CHARGEMENT ET PRÉPARATION DES DONNÉES
# ══════════════════════════════════════════════════════════════════

def nettoyer_texte(texte):
    texte = str(texte).lower()
    texte = re.sub(r'http\S+', ' URL ', texte)
    texte = re.sub(r'\S+@\S+', ' EMAIL ', texte)
    texte = re.sub(r'[^a-zA-Z0-9\s]', ' ', texte)
    texte = re.sub(r'\s+', ' ', texte).strip()
    return texte


def extraire_urls(texte):
    return re.findall(r'http[s]?://[^\s<>"{}|\\^`\[\]]+', str(texte))


def extraire_domaine(sender):
    m = re.search(r'@([\w.\-]+)', str(sender))
    return m.group(1).lower() if m else 'unknown'


def preparer_dataset(csv_path: str):
    print("⏳ Chargement du dataset CEAS_08...")
    df = pd.read_csv(csv_path, encoding="utf-8", on_bad_lines="skip")
    df = df.copy()
    df['subject']  = df['subject'].fillna('')
    df['body']     = df['body'].fillna('')
    df['sender']   = df['sender'].fillna('')
    df = df.drop_duplicates(subset=['subject', 'body'])
    print(f"✅ {len(df)} emails chargés — distribution : {df['label'].value_counts().to_dict()}")

    # Nettoyage texte
    df['subject_clean'] = df['subject'].apply(nettoyer_texte)
    df['body_clean']    = df['body'].apply(nettoyer_texte)

    # Features numériques (identiques à trainer.py)
    df['urls_extraites']          = df['body'].apply(extraire_urls)
    df['subject_length']          = df['subject'].apply(lambda x: len(str(x)))
    df['body_length']             = df['body'].apply(lambda x: len(str(x)))
    df['word_count']              = df['body_clean'].apply(lambda x: len(str(x).split()))
    df['urgency_score']           = df['body_clean'].apply(lambda x: sum(1 for m in MOTS_URGENTS if m in str(x)))
    df['has_url']                 = df['body_clean'].apply(lambda x: 1 if 'url' in str(x) else 0)
    df['caps_ratio']              = df['subject'].apply(lambda x: sum(1 for c in str(x) if c.isupper()) / max(len(str(x)),1))
    df['exclamation_count']       = df['body'].apply(lambda x: str(x).count('!'))
    df['question_count']          = df['body'].apply(lambda x: str(x).count('?'))
    df['html_tags_count']         = df['body'].apply(lambda x: len(re.findall(r'<[^>]+>', str(x))))
    df['url_count']               = df['urls_extraites'].apply(len)
    df['url_length_avg']          = df['urls_extraites'].apply(lambda u: round(sum(len(x) for x in u)/len(u),2) if u else 0)
    df['has_ip_in_url']           = df['urls_extraites'].apply(lambda u: 1 if any(re.search(r'http[s]?://\d{1,3}(\.\d{1,3}){3}',x) for x in u) else 0)
    df['url_obfuscated']          = df['urls_extraites'].apply(lambda u: 1 if any(s in x for x in u for s in ['%40','%20','0x']) else 0)
    df['subdomain_count']         = df['urls_extraites'].apply(lambda u: max((len(re.sub(r'https?://','',x).split('/')[0].split('.'))-2 for x in u), default=0))
    df['suspicious_url_keywords'] = df['urls_extraites'].apply(lambda u: sum(1 for x in u for k in ['login','verify','secure','account','confirm'] if k in x.lower()))
    df['url_has_https']           = df['urls_extraites'].apply(lambda u: 1 if any(x.startswith('https') for x in u) else 0)
    df['url_tld_suspect']         = df['urls_extraites'].apply(lambda u: 1 if any(t in x.lower() for x in u for t in TLDS_SUSPECTS) else 0)

    df['sender_domain']             = df['sender'].apply(extraire_domaine)
    df['sender_domain_length']      = df['sender_domain'].apply(len)
    df['sender_has_numbers']        = df['sender_domain'].apply(lambda d: 1 if re.search(r'\d', d) else 0)
    df['sender_domain_suspicious']  = df['sender_domain'].apply(lambda d: 1 if any(w in d for w in ['secure','verify','login','account','update']) else 0)
    df['sender_tld_suspect']        = df['sender_domain'].apply(lambda d: 1 if any(d.endswith(t) for t in TLDS_SUSPECTS) else 0)

    def mismatch(sender):
        m = re.search(r'^([^<]+)<', str(sender))
        nom = m.group(1).strip().lower() if m else ''
        dom = extraire_domaine(sender)
        for marque in ['paypal','google','amazon','apple','microsoft','facebook','netflix']:
            if marque in nom and marque not in dom:
                return 1
        return 0

    df['display_name_mismatch'] = df['sender'].apply(mismatch)
    df['text_combined']         = df['subject_clean'] + ' ' + df['body_clean']

    return df


# ══════════════════════════════════════════════════════════════════
# ÉVALUATION
# ══════════════════════════════════════════════════════════════════

def evaluer_modele(model_name: str, model, X_test, y_test) -> dict:
    print(f"\n📊 Évaluation : {model_name}")

    # Prédictions
    start      = time.time()
    y_pred     = model.predict(X_test)
    temps_pred = time.time() - start

    # Métriques
    acc       = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall    = recall_score(y_test, y_pred, zero_division=0)
    f1        = f1_score(y_test, y_pred, zero_division=0)
    cm        = confusion_matrix(y_test, y_pred)

    tn, fp, fn, tp = cm.ravel()
    faux_positifs  = fp / (fp + tn) * 100  # taux faux positifs
    taux_detection = recall * 100           # recall = taux détection

    # AUC-ROC si disponible
    auc = None
    try:
        if hasattr(model, "decision_function"):
            scores = model.decision_function(X_test)
        elif hasattr(model, "predict_proba"):
            scores = model.predict_proba(X_test)[:, 1]
        else:
            scores = None
        if scores is not None:
            auc = roc_auc_score(y_test, scores)
    except Exception:
        pass

    # Affichage
    print(f"  Accuracy          : {acc*100:.2f}%")
    print(f"  Précision         : {precision*100:.2f}%")
    print(f"  Recall (détection): {recall*100:.2f}%")
    print(f"  F1-Score          : {f1*100:.2f}%")
    if auc:
        print(f"  AUC-ROC           : {auc:.4f}")
    print(f"  Faux positifs     : {faux_positifs:.2f}%")
    print(f"  Matrice confusion : TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"  Temps prédiction  : {temps_pred:.3f}s pour {len(y_test)} emails")
    print(f"  Temps par email   : {temps_pred/len(y_test)*1000:.2f}ms")

    # Vérification critères PCD
    print(f"\n  Critères PCD :")
    print(f"  BD-02 Faux positifs < 5%  : {'✅' if faux_positifs < 5 else '❌'} ({faux_positifs:.2f}%)")
    print(f"  BD-03 Détection ≥ 95%     : {'✅' if taux_detection >= 95 else '❌'} ({taux_detection:.2f}%)")

    return {
        "model":           model_name,
        "accuracy":        round(acc * 100, 2),
        "precision":       round(precision * 100, 2),
        "recall":          round(recall * 100, 2),
        "f1_score":        round(f1 * 100, 2),
        "auc_roc":         round(auc, 4) if auc else None,
        "faux_positifs":   round(faux_positifs, 2),
        "taux_detection":  round(taux_detection, 2),
        "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
        "temps_total_s":   round(temps_pred, 3),
        "temps_par_email_ms": round(temps_pred / len(y_test) * 1000, 2),
        "bd02_ok": bool(faux_positifs < 5),
        "bd03_ok": bool(taux_detection >= 95),
    }


# ══════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 60)
    print("  ÉVALUATION DES MODÈLES — PhishGuard AI")
    print("=" * 60)

    # 1. Préparer les données
    df = preparer_dataset(CSV_PATH)

    # 2. Charger les artefacts
    print("\n⏳ Chargement des modèles sauvegardés...")
    tfidf  = joblib.load(MODELS_DIR / "tfidf_vectorizer.pkl")
    scaler = joblib.load(MODELS_DIR / "scaler.pkl")
    svm    = joblib.load(MODELS_DIR / "svm.pkl")
    rf     = joblib.load(MODELS_DIR / "random_forest.pkl")
    xgb    = joblib.load(MODELS_DIR / "xgboost.pkl")
    print("✅ Modèles chargés")

    # 3. Construire X et y
    X_num    = df[FEATURE_NAMES].values
    X_scaled = scaler.transform(X_num)
    X_tfidf  = tfidf.transform(df['text_combined'])
    X_final  = sp.hstack([sp.csr_matrix(X_scaled), X_tfidf])
    y        = df['label'].values

    # 4. Split identique à l'entraînement (même random_state=42)
    _, X_test, _, y_test = train_test_split(
        X_final, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"\n✅ Jeu de test : {len(y_test)} emails "
          f"({sum(y_test==1)} phishing / {sum(y_test==0)} légitimes)")

    # 5. Évaluer les 3 modèles
    resultats = []
    resultats.append(evaluer_modele("SVM (LinearSVC)",    svm, X_test, y_test))
    resultats.append(evaluer_modele("Random Forest",      rf,  X_test, y_test))
    resultats.append(evaluer_modele("XGBoost",            xgb, X_test, y_test))

    # 6. Tableau comparatif final
    print(f"\n{'=' * 60}")
    print("  TABLEAU COMPARATIF FINAL")
    print(f"{'=' * 60}")
    print(f"  {'Modèle':<20} {'Accuracy':>9} {'Recall':>8} {'F1':>8} {'FP%':>7} {'AUC':>7}")
    print(f"  {'-'*55}")
    for r in resultats:
        auc_str = f"{r['auc_roc']:.4f}" if r['auc_roc'] else "  N/A "
        print(f"  {r['model']:<20} {r['accuracy']:>8}% {r['recall']:>7}% "
              f"{r['f1_score']:>7}% {r['faux_positifs']:>6}% {auc_str:>7}")

    # 7. Sauvegarde JSON pour le rapport
    os.makedirs("tests/evaluation", exist_ok=True)
    with open("tests/evaluation/resultats_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(resultats, f, indent=2, ensure_ascii=False)
    print(f"\n✅ Résultats sauvegardés dans tests/evaluation/resultats_evaluation.json")
    print(f"{'=' * 60}")