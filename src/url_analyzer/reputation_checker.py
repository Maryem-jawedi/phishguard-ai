import requests
import socket
import dns.resolver
from datetime import datetime
import whois


KNOWN_LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com"
]


def check_reputation(domain: str) -> dict:
    return {
        "is_known_legitimate": check_known_legitimate(domain),
        "domain_age_days":     get_domain_age(domain),
        "has_mx_record":       check_mx_record(domain),
        "has_a_record":        check_a_record(domain),
        "in_blacklist":        check_blacklist(domain),
    }


def check_known_legitimate(domain: str) -> int:
    return int(domain.lower() in KNOWN_LEGITIMATE_DOMAINS)


def get_domain_age(domain: str) -> int:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            delta = datetime.now() - creation_date
            return delta.days
        return -1
    except Exception:
        return -1


def check_mx_record(domain: str) -> int:
    try:
        dns.resolver.resolve(domain, "MX")
        return 1
    except Exception:
        return 0


def check_a_record(domain: str) -> int:
    try:
        socket.gethostbyname(domain)
        return 1
    except Exception:
        return 0


def check_blacklist(domain: str) -> int:
    try:
        # placeholder — à connecter avec Google Safe Browsing API
        # api_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
        # pour l'instant retourne 0 par défaut
        return 0
    except Exception:
        return 0


def get_domain_reputation_score(domain: str) -> float:
    """
    Calcule un score global de réputation entre 0 (suspect) et 1 (légitime)
    basé sur tous les checks disponibles
    """
    results = check_reputation(domain)

    score = 0.0
    weights = {
        "is_known_legitimate": 0.4,
        "domain_age_days":     0.3,
        "has_mx_record":       0.15,
        "has_a_record":        0.15,
    }

    score += results["is_known_legitimate"] * weights["is_known_legitimate"]

    # domaine âgé de plus d'un an = bon signe
    age = results["domain_age_days"]
    if age > 365:
        score += weights["domain_age_days"]
    elif age > 90:
        score += weights["domain_age_days"] * 0.5

    score += results["has_mx_record"] * weights["has_mx_record"]
    score += results["has_a_record"] * weights["has_a_record"]

    # blacklist annule tout
    if results["in_blacklist"]:
        return 0.0

    return round(score, 4)