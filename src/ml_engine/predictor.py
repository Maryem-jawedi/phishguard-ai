import joblib
import numpy as np
import scipy.sparse as sp
import math
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent.parent / "modeles_sauvegardes"

# 22 features numériques — ordre identique à l'entraînement
FEATURE_NAMES = [
    # Groupe 1 — texte (9 features)
    "subject_length", "body_length", "word_count",
    "urgency_score", "caps_ratio", "has_url",           # has_url corrigé
    "exclamation_count", "question_count", "html_tags_count",
    # Groupe 2 — URL (8 features)
    "url_count", "url_length_avg", "has_ip_in_url",
    "url_obfuscated", "subdomain_count", "suspicious_url_keywords",
    "url_has_https", "url_tld_suspect",                 # url_tld_suspect corrigé
    # Groupe 3 — expéditeur (5 features)
    "sender_domain_length", "sender_has_numbers",
    "sender_domain_suspicious", "sender_tld_suspect",   # sender_tld_suspect corrigé
    "display_name_mismatch",
]

# Règles réseau niveau 1 — avec poids
# Format : (feature, valeur_suspecte, poids, raison)
NETWORK_RULES = [
    ("in_blacklist",         1,   1.0,  "Domaine dans blacklist Google"),
    ("spf_valid",            0,   0.4,  "SPF invalide — expéditeur non autorisé"),
    ("dkim_valid",           0,   0.35, "DKIM invalide — email non signé"),
    ("dmarc_valid",          0,   0.25, "DMARC invalide — aucune politique email"),
    ("ssl_valid",            0,   0.3,  "SSL invalide — site non sécurisé"),
    ("sender_ip_reputation", 1,   0.9,  "IP expéditeur signalée comme malveillante"),
]

# Seuil de score cumulé pour bloquer au niveau 1
# (évite les faux positifs sur un seul check DNS échoué)
NETWORK_BLOCK_THRESHOLD = 0.75


class PhishingPredictor:

    def __init__(self):
        self.model  = joblib.load(MODELS_DIR / "svm.pkl")
        self.tfidf  = joblib.load(MODELS_DIR / "tfidf_vectorizer.pkl")
        self.scaler = joblib.load(MODELS_DIR / "scaler.pkl")

    def predict(self, features: dict, text_combined: str) -> dict:
        """
        Pipeline en cascade :
        Niveau 1 → vérification réseau (score cumulé)
        Niveau 2 → modèle SVM (si niveau 1 passe)
        Niveau 3 → ajustement âge domaine
        """

        # ── NIVEAU 1 — Filtrage réseau ──────────────────────────────────
        network_result = self._check_network_rules(features)

        if network_result["blocked"]:
            return {
                "is_phishing"   : True,
                "confidence"    : round(network_result["score"] * 100, 2),
                "risk_level"    : "CRITIQUE",
                "label"         : "PHISHING",
                "blocked_at"    : "NIVEAU 1 — Vérification réseau",
                "block_reason"  : network_result["reason"],
                "svm_used"      : False,
                "network_flags" : self._network_flags(features),
            }

        # ── NIVEAU 2 — Modèle SVM ───────────────────────────────────────
        num_vector = np.array([
            features.get(f, 0) for f in FEATURE_NAMES
        ], dtype=float).reshape(1, -1)

        num_scaled   = self.scaler.transform(num_vector)
        tfidf_vector = self.tfidf.transform([text_combined])
        X            = sp.hstack([sp.csr_matrix(num_scaled), tfidf_vector])

        prediction     = int(self.model.predict(X)[0])
        decision_score = float(self.model.decision_function(X)[0])
        confidence     = round(100 / (1 + math.exp(-decision_score)), 2)

        # ── NIVEAU 3 — Ajustement âge domaine ──────────────────────────
        age = features.get("domain_age_days", -1)
        age_warning = None

        if age != -1 and age < 7:
            confidence  = min(confidence + 20, 100)
            age_warning = f"Domaine très jeune ({age} jours) → très suspect"
        elif age != -1 and age < 30:
            confidence  = min(confidence + 10, 100)
            age_warning = f"Domaine jeune ({age} jours) → suspect"

        final_prediction = 1 if confidence >= 50 else 0

        return {
            "is_phishing"   : bool(final_prediction),
            "confidence"    : confidence,
            "risk_level"    : self._risk_level(confidence / 100),
            "label"         : "PHISHING" if final_prediction == 1 else "LÉGITIME",
            "blocked_at"    : "NIVEAU 2 — Modèle SVM",
            "block_reason"  : age_warning,
            "svm_used"      : True,
            "network_flags" : self._network_flags(features),
        }

    def _check_network_rules(self, features: dict) -> dict:
        """
        Niveau 1 — score cumulé sur les règles réseau.
        Bloque immédiatement sur : blacklist=1 ou ip_reputation=1.
        Pour les autres (SPF/DKIM/DMARC/SSL) : score cumulé > seuil requis.
        """
        cumulative_score = 0.0
        triggered_reasons = []

        for feature, valeur_suspecte, poids, raison in NETWORK_RULES:
            valeur_reelle = features.get(feature, None)
            if valeur_reelle is None:
                continue  # feature non disponible → on skip sans pénaliser

            if valeur_reelle == valeur_suspecte:
                # Blocage immédiat pour les règles critiques
                if poids >= 0.9:
                    return {
                        "blocked": True,
                        "score"  : poids,
                        "reason" : raison,
                    }
                cumulative_score += poids
                triggered_reasons.append(raison)

        if cumulative_score >= NETWORK_BLOCK_THRESHOLD:
            return {
                "blocked": True,
                "score"  : min(cumulative_score, 1.0),
                "reason" : " | ".join(triggered_reasons),
            }

        return {"blocked": False, "score": cumulative_score, "reason": None}

    def _network_flags(self, features: dict) -> dict:
        return {
            "spf_valid"           : features.get("spf_valid",            "non vérifié"),
            "dkim_valid"          : features.get("dkim_valid",           "non vérifié"),
            "dmarc_valid"         : features.get("dmarc_valid",          "non vérifié"),
            "ssl_valid"           : features.get("ssl_valid",            "non vérifié"),
            "domain_age_days"     : features.get("domain_age_days",      "non vérifié"),
            "in_blacklist"        : features.get("in_blacklist",         "non vérifié"),
            "sender_ip_reputation": features.get("sender_ip_reputation", "non vérifié"),
        }

    @staticmethod
    def _risk_level(proba: float) -> str:
        if proba >= 0.8: return "CRITIQUE"
        if proba >= 0.6: return "ÉLEVÉ"
        if proba >= 0.4: return "MODÉRÉ"
        return "FAIBLE"