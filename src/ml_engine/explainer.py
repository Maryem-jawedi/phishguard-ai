import shap
import numpy as np
import joblib
from pathlib import Path

MODELS_DIR = Path(__file__).parent.parent.parent / "modeles_sauvegardes"

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


class PhishingExplainer:

    def __init__(self):
        rf_model = joblib.load(MODELS_DIR / "random_forest.pkl")
        self.explainer = shap.TreeExplainer(rf_model)

    def explain(self, features: dict) -> dict:
        """
        Reçoit le dict de features d'un email et retourne
        les top facteurs qui ont influencé la décision.
        """
        num_vector = np.array([
            features.get(f, 0) for f in FEATURE_NAMES
        ], dtype=float).reshape(1, -1)

        shap_values = self.explainer.shap_values(num_vector)

        # Gestion robuste selon la version de SHAP et le type de modèle :
        # - SHAP < 0.40 + RandomForest : retourne une liste [classe_0, classe_1]
        # - SHAP >= 0.40 : peut retourner un array 3D (n_samples, n_features, n_classes)
        if isinstance(shap_values, list):
            # format liste — on prend la classe 1 (phishing)
            valeurs = np.array(shap_values[1]).flatten()
        elif hasattr(shap_values, "ndim") and shap_values.ndim == 3:
            # format 3D array
            valeurs = shap_values[0, :, 1]
        else:
            # format 2D array (binaire ou régression)
            valeurs = np.array(shap_values).flatten()

        indices = np.argsort(np.abs(valeurs))[::-1]

        top_factors = []
        for i in indices[:8]:
            top_factors.append({
                "feature": FEATURE_NAMES[i],
                "score"  : round(float(valeurs[i]), 4),
                "effect" : "PHISHING" if valeurs[i] > 0 else "LÉGITIME",
            })

        return {"top_factors": top_factors}