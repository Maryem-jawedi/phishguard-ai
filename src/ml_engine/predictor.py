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
    "urgency_score", "caps_ratio", "has_url",
    "exclamation_count", "question_count", "html_tags_count",
    # Groupe 2 — URL (8 features)
    "url_count", "url_length_avg", "has_ip_in_url",
    "url_obfuscated", "subdomain_count", "suspicious_url_keywords",
    "url_has_https", "url_tld_suspect",
    # Groupe 3 — expéditeur (5 features)
    "sender_domain_length", "sender_has_numbers",
    "sender_domain_suspicious", "sender_tld_suspect",
    "display_name_mismatch",
]

# Seuil de score cumulé pour bloquer au niveau 1
NETWORK_BLOCK_THRESHOLD = 0.75

# ──────────────────────────────────────────────────────────────────────────────
# CALIBRATION — LinearSVC produit des scores bruts très élevés (±5 à ±15).
# Sans calibration, la sigmoid donne 99-100 % pour presque tout, rendant les
# ajustements post-SVM insuffisants.  Diviser par SVM_CALIBRATION "étale" la
# distribution et ramène les scores dans une plage exploitable.
# ──────────────────────────────────────────────────────────────────────────────
SVM_CALIBRATION = 3.0


class PhishingPredictor:

    def __init__(self):
        self.model  = joblib.load(MODELS_DIR / "svm.pkl")
        self.tfidf  = joblib.load(MODELS_DIR / "tfidf_vectorizer.pkl")
        self.scaler = joblib.load(MODELS_DIR / "scaler.pkl")

    def predict(self, features: dict, text_combined: str) -> dict:
        """
        Pipeline en cascade :
        Niveau 1 → vérification réseau (score cumulé, TLD-aware)
        Niveau 2 → modèle SVM calibré (si niveau 1 passe)
        Niveau 3 → ajustements post-SVM (âge domaine + légitimité réseau + contenu)
        """

        # ── NIVEAU 1 — Filtrage réseau ────────────────────────────────────────
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

        # ── NIVEAU 2 — Modèle SVM calibré ────────────────────────────────────
        num_vector = np.array([
            features.get(f, 0) for f in FEATURE_NAMES
        ], dtype=float).reshape(1, -1)

        num_scaled   = self.scaler.transform(num_vector)
        tfidf_vector = self.tfidf.transform([text_combined])
        X            = sp.hstack([sp.csr_matrix(num_scaled), tfidf_vector])

        prediction     = int(self.model.predict(X)[0])
        decision_score = float(self.model.decision_function(X)[0])

        # ── Calibration : amortit les scores extrêmes du LinearSVC ──────────
        decision_score_calibrated = decision_score / SVM_CALIBRATION
        confidence = round(100 / (1 + math.exp(-decision_score_calibrated)), 2)

        # ── NIVEAU 3 — Ajustements post-SVM ──────────────────────────────────

        # Ajustement à la hausse si domaine jeune
        age = features.get("domain_age_days", -1)
        age_warning = None

        if age != -1 and age < 7:
            confidence  = min(confidence + 20, 100)
            age_warning = f"Domaine très jeune ({age} jours) → très suspect"
        elif age != -1 and age < 30:
            confidence  = min(confidence + 10, 100)
            age_warning = f"Domaine jeune ({age} jours) → suspect"

        # Calcul de la légitimité réseau
        spf         = features.get("spf_valid",          0)
        dmarc       = features.get("dmarc_valid",        0)
        ssl         = features.get("ssl_valid",          0)
        dkim        = features.get("dkim_valid",         0)
        tld_suspect = features.get("sender_tld_suspect", 0)

        legitimacy_score = spf + dmarc + ssl + dkim  # max = 4

        # ── Comptage des signaux suspects dans le contenu de l'email ─────────
        # Permet de distinguer un email propre d'un email ambigu quand les DNS
        # sont inconnus ou absents (ex : domaine interne, TLD normal).
        suspicious_signals = sum([
            int(features.get("has_ip_in_url",           0) == 1),
            int(features.get("url_obfuscated",          0) == 1),
            int(features.get("display_name_mismatch",   0) == 1),
            int(features.get("sender_domain_suspicious",0) == 1),
            int(features.get("urgency_score",           0) > 0.3),
            int(features.get("url_tld_suspect",         0) == 1),
            int(features.get("suspicious_url_keywords", 0) > 0),
        ])

        if legitimacy_score >= 3:
            # DNS valides et nombreux → domaine clairement légitime
            confidence = max(confidence - 40, 0)
        elif legitimacy_score == 2:
            confidence = max(confidence - 20, 0)
        elif legitimacy_score == 1:
            confidence = max(confidence - 8, 0)
        elif legitimacy_score == 0 and tld_suspect == 0:
            # DNS inconnus ou absents, TLD normal (.fr, .com, .tn, .org…)
            # → ajustement selon la propreté du contenu
            if suspicious_signals == 0:
                # Email totalement propre : pas d'IP, pas d'urgence, pas de
                # mismatch, pas de mots suspects → bénéfice du doute maximal
                confidence = max(confidence - 65, 0)
                print(f"[DEBUG] email propre (0 signaux) : -65 % → confidence={confidence}")
            else:
                # Contenu partiellement suspect mais DNS inconnus : réduction
                # modérée — le SVM a peut-être raison
                confidence = max(confidence - 35, 0)
                print(f"[DEBUG] signaux={suspicious_signals}, DNS inconnus : -35 % → confidence={confidence}")
        # Si legitimacy_score == 0 ET tld_suspect == 1 → pas d'ajustement
        # Le SVM seul décide (conservateur).

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
        Niveau 1 — Filtrage réseau TLD-aware.

        Logique :
        - Blocage immédiat sur blacklist ou IP malveillante (signaux critiques)
        - Sur TLD suspect (.tk, .xyz, .ml…) : SPF/DKIM/DMARC/SSL invalides
          sont de vrais signaux → score cumulé
        - URL avec TLD suspect + HTTP non sécurisé → signal URL-only fort
          (cas d'analyse d'URL seule, sans expéditeur)
        - Sur TLD normal (.fr, .com, .tn…) : absence de SPF/DKIM = domaine
          mal configuré, pas nécessairement phishing → on ne pénalise pas
        """
        cumulative_score  = 0.0
        triggered_reasons = []

        # Blocage immédiat sur signaux critiques
        if features.get("in_blacklist", 0) == 1:
            return {
                "blocked": True,
                "score"  : 1.0,
                "reason" : "Domaine dans blacklist Google",
            }

        if features.get("sender_ip_reputation", 0) == 1:
            return {
                "blocked": True,
                "score"  : 0.9,
                "reason" : "IP expéditeur signalée comme malveillante",
            }

        # ── Détection URL-only : TLD suspect + absence de HTTPS ──────────────
        # Ce cas couvre l'analyse d'URL seule (pas d'expéditeur, DNS email = 0
        # par construction).  On l'évalue avant les blocs SPF/DKIM car ces
        # derniers ne sont pas pertinents pour une URL isolée.
        url_tld_suspect = features.get("url_tld_suspect", 0) == 1
        url_no_https    = features.get("url_has_https",   1) == 0
        has_ip_in_url   = features.get("has_ip_in_url",   0) == 1

        # Blocage immédiat sur signaux URL forts (sans dépendance aux DNS email)
        if url_tld_suspect and url_no_https:
            return {
                "blocked": True,
                "score"  : 0.85,
                "reason" : "TLD suspect + URL non sécurisée (HTTP)",
            }

        if has_ip_in_url and url_no_https:
            return {
                "blocked": True,
                "score"  : 0.80,
                "reason" : "Adresse IP dans URL + absence de HTTPS",
            }

        # URL HTTP avec accumulation de mots suspects (ex : /login/verify/account)
        sus_kw = features.get("suspicious_url_keywords", 0)
        if url_no_https and sus_kw >= 3:
            return {
                "blocked": True,
                "score"  : 0.78,
                "reason" : f"URL HTTP avec {sus_kw} mots suspects (login/verify/account…)",
            }

        # ── SPF/DKIM/DMARC/SSL : pénaliser UNIQUEMENT sur TLD expéditeur suspect ──
        sender_tld_suspect = (
            features.get("sender_tld_suspect", 0) == 1 or
            features.get("url_tld_suspect",    0) == 1
        )

        if sender_tld_suspect:
            # TLD gratuit/malveillant → l'absence de DNS est un vrai signal
            if features.get("spf_valid",   0) == 0:
                cumulative_score += 0.40
                triggered_reasons.append("SPF invalide — expéditeur non autorisé")
            if features.get("dkim_valid",  0) == 0:
                cumulative_score += 0.35
                triggered_reasons.append("DKIM invalide — email non signé")
            if features.get("dmarc_valid", 0) == 0:
                cumulative_score += 0.25
                triggered_reasons.append("DMARC invalide — aucune politique email")
            if features.get("ssl_valid",   0) == 0:
                cumulative_score += 0.30
                triggered_reasons.append("SSL invalide — site non sécurisé")
        else:
            # TLD normal (.fr, .com, .tn…) → DNS absent = neutre
            # Seule exception : SSL absent + IP dans URL (très suspect)
            if features.get("ssl_valid", 0) == 0 and has_ip_in_url:
                cumulative_score += 0.30
                triggered_reasons.append("SSL invalide avec adresse IP dans URL")

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