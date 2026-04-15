from fastapi import APIRouter, HTTPException, Depends
from src.api.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse,
    URLAnalysisRequest, URLAnalysisResponse
)
from src.api.auth import get_current_active_user
from src.email_analyzer.parser import parse_email
from src.email_analyzer.feature_extractor import extract_features
from src.url_analyzer.url_parser import parse_urls, get_url_length_avg
from src.url_analyzer.feature_extractor import extract_url_features
from src.ml_engine.predictor import PhishingPredictor
from fastapi import Depends
from src.api.auth import get_current_user

router = APIRouter()


# explainer = PhishingExplainer()

# Instance unique du predictor (chargée une seule fois au démarrage)
predictor = PhishingPredictor()


# ══════════════════════════════════════════════════════════════════
# ROUTE : analyse d'un email complet (protégée JWT)
# ══════════════════════════════════════════════════════════════════

@router.post("/analyze/email", response_model=EmailAnalysisResponse, tags=["Analyse"])
async def analyze_email(
    request: EmailAnalysisRequest,
    current_user=Depends(get_current_active_user)   # ← protection JWT
):
    try:
        parsed        = parse_email(request.raw_email)
        features      = extract_features(parsed)
        features_clean = {k: (0 if v is None else v) for k, v in features.items()}
        text_combined = parsed.subject + " " + parsed.body
        prediction    = predictor.predict(features_clean, text_combined)
        suspicious    = _get_suspicious_elements(features_clean)
        report        = _generate_report(features_clean, suspicious, prediction)

        return EmailAnalysisResponse(
            is_phishing=int(prediction["is_phishing"]),
            confidence=prediction["confidence"],
            features=features_clean,
            suspicious_elements=suspicious,
            report=report
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════════
# ROUTE : analyse d'une URL seule (protégée JWT)
# ══════════════════════════════════════════════════════════════════

@router.post("/analyze/url", response_model=URLAnalysisResponse, tags=["Analyse"])
async def analyze_url(
    request: URLAnalysisRequest,
    current_user=Depends(get_current_active_user)   # ← protection JWT
):
    try:
        features       = extract_url_features([request.url])
        features_clean = {k: (0 if v is None else v) for k, v in features.items()}
        full_features  = _build_full_features_from_url(features_clean)
        text_combined  = request.url
        prediction     = predictor.predict(full_features, text_combined)
        suspicious     = _get_url_suspicious_elements(features_clean)

        return URLAnalysisResponse(
            url=request.url,
            is_phishing=int(prediction["is_phishing"]),
            confidence=prediction["confidence"],
            features=features_clean,
            suspicious_elements=suspicious
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def _build_full_features_from_url(url_features: dict) -> dict:
    from src.ml_engine.predictor import FEATURE_NAMES
    base = {f: 0 for f in FEATURE_NAMES}
    base.update({
        "spf_valid": 0, "dkim_valid": 0, "dmarc_valid": 0,
        "ssl_valid": 0, "domain_age_days": -1,
        "in_blacklist": 0, "sender_ip_reputation": 0,
    })
    base.update(url_features)
    return base


def _get_suspicious_elements(features: dict) -> list[str]:
    suspicious = []
    if features.get("urgency_score", 0) > 0.3:
        suspicious.append("Langage urgent détecté dans le corps")
    if features.get("spf_valid", 1) == 0:
        suspicious.append("SPF invalide — expéditeur non vérifié")
    if features.get("dkim_valid", 1) == 0 and features.get("spf_valid", 1) == 0:
        suspicious.append("DKIM invalide — email potentiellement falsifié")
    if features.get("dmarc_valid", 1) == 0:
        suspicious.append("DMARC invalide")
    if features.get("has_ip_in_url", 0) == 1:
        suspicious.append("URL contient une adresse IP")
    if features.get("url_obfuscated", 0) == 1:
        suspicious.append("URL obfusquée détectée")
    if features.get("display_name_mismatch", 0) == 1:
        suspicious.append("Nom affiché ne correspond pas au domaine réel")
    if features.get("sender_domain_suspicious", 0) == 1:
        suspicious.append("Domaine expéditeur suspect")
    if features.get("caps_ratio", 0) > 0.5:
        suspicious.append("Trop de majuscules dans le sujet")
    if features.get("exclamation_count", 0) > 3:
        suspicious.append("Trop de points d'exclamation")
    if features.get("url_tld_suspect", 0) == 1:
        suspicious.append("TLD suspect dans l'URL (.tk, .xyz, .ru...)")
    if features.get("sender_tld_suspect", 0) == 1:
        suspicious.append("TLD suspect dans le domaine expéditeur")
    if features.get("url_count", 0) > 0 and features.get("url_has_https", 1) == 0:
        suspicious.append("URL sans HTTPS")
    return suspicious


def _get_url_suspicious_elements(features: dict) -> list[str]:
    suspicious = []
    if features.get("has_ip_in_url", 0) == 1:
        suspicious.append("URL contient une adresse IP")
    if features.get("url_obfuscated", 0) == 1:
        suspicious.append("URL obfusquée")
    if features.get("url_has_https", 1) == 0:
        suspicious.append("URL sans HTTPS")
    if features.get("has_shortened_url", 0) == 1:
        suspicious.append("URL raccourcie détectée")
    if features.get("suspicious_url_keywords", 0) > 0:
        suspicious.append("Mots suspects dans l'URL")
    if features.get("url_tld_suspect", 0) == 1:
        suspicious.append("TLD suspect (.tk, .xyz, .ru...)")
    return suspicious


def _generate_report(features: dict, suspicious: list[str], prediction: dict) -> str:
    label      = prediction.get("label", "INCONNU")
    confidence = prediction.get("confidence", 0)
    risk       = prediction.get("risk_level", "")
    blocked_at = prediction.get("blocked_at", "")
    reason     = prediction.get("block_reason", "")

    lines = []
    lines.append(f"{'⚠' if prediction.get('is_phishing') else '✅'} VERDICT : {label}")
    lines.append(f"   Confiance     : {confidence}%")
    lines.append(f"   Niveau risque : {risk}")
    lines.append(f"   Détecté par   : {blocked_at}")
    if reason:
        lines.append(f"   Raison        : {reason}")

    if suspicious:
        lines.append(f"\n⚠️  {len(suspicious)} élément(s) suspect(s) :")
        for elem in suspicious:
            lines.append(f"   - {elem}")
    else:
        lines.append("\nAucun élément suspect supplémentaire détecté.")

    return "\n".join(lines)