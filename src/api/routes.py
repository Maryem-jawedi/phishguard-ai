from fastapi import APIRouter, HTTPException
from src.api.schemas import (
    EmailAnalysisRequest, EmailAnalysisResponse,
    URLAnalysisRequest, URLAnalysisResponse
)
from src.email_analyzer.parser import parse_email
from src.email_analyzer.feature_extractor import extract_features
from src.url_analyzer.url_parser import parse_url
from src.url_analyzer.feature_extractor import extract_url_features


router = APIRouter()


@router.post("/analyze/email", response_model=EmailAnalysisResponse)
async def analyze_email(request: EmailAnalysisRequest):
    try:
        # -- parsing
        parsed = parse_email(request.raw_email)

        # -- extraction features
        features = extract_features(parsed)

        # -- éléments suspects
        suspicious = _get_suspicious_elements(features)

        # -- rapport lisible
        report = _generate_report(features, suspicious)

        return EmailAnalysisResponse(
            is_phishing=None,       # sera rempli par Lina (ML engine)
            confidence=None,        # sera rempli par Lina (ML engine)
            features=features,
            suspicious_elements=suspicious,
            report=report
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    try:
        # -- extraction features URL
        features = extract_url_features([request.url])

        # -- éléments suspects
        suspicious = _get_url_suspicious_elements(features)

        return URLAnalysisResponse(
            url=request.url,
            is_phishing=None,       # sera rempli par Lina
            confidence=None,        # sera rempli par Lina
            features=features,
            suspicious_elements=suspicious
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _get_suspicious_elements(features: dict) -> list[str]:
    suspicious = []
    if features.get("urgency_score", 0) > 0.3:
        suspicious.append("Langage urgent détecté dans le corps")
    if features.get("spf_valid", 1) == 0:
        suspicious.append("SPF invalide — expéditeur non vérifié")
    if features.get("dkim_valid", 1) == 0:
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
    return suspicious


def _generate_report(features: dict, suspicious: list[str]) -> str:
    if not suspicious:
        return "Aucun élément suspect détecté. Email probablement légitime."
    report = f"⚠️ {len(suspicious)} élément(s) suspect(s) détecté(s) :\n"
    for element in suspicious:
        report += f"  - {element}\n"
    return report