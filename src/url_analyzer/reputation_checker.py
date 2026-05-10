import socket
import dns.resolver
from datetime import datetime
import whois

KNOWN_LEGITIMATE_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "netflix.com", "twitter.com",
    "instagram.com", "linkedin.com", "github.com", "youtube.com",
    "wikipedia.org", "stackoverflow.com", "medium.com",
    "pypi.org", "aws.amazon.com", "docs.aws.amazon.com",
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
    if not domain or domain == "unknown":
        return 0
    domain_lower = domain.lower()
    # Vérifie aussi les sous-domaines (ex: www.google.com → google.com)
    for legit in KNOWN_LEGITIMATE_DOMAINS:
        if domain_lower == legit or domain_lower.endswith("." + legit):
            return 1
    return 0


def get_domain_age(domain: str) -> int:
    try:
        if not domain or domain == "unknown" or "." not in domain:
            return -1
        # Les domaines connus : pas besoin de whois, on évite le rate-limit
        if check_known_legitimate(domain) == 1:
            return 3650  # ~10 ans — domaine légitime connu
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
        if not domain or domain == "unknown":
            return 0
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3
        resolver.timeout = 3
        resolver.resolve(domain, "MX")
        return 1
    except Exception:
        return 0


def check_a_record(domain: str) -> int:
    try:
        if not domain or domain == "unknown":
            return 0
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        socket.setdefaulttimeout(None)
        return 1
    except Exception:
        socket.setdefaulttimeout(None)
        return 0


def check_blacklist(domain: str) -> int:
    try:
        # placeholder — à connecter avec Google Safe Browsing API
        return 0
    except Exception:
        return 0


def get_domain_reputation_score(domain: str) -> float:
    if not domain or domain == "unknown":
        return 0.0

    try:
        results = check_reputation(domain)
    except Exception:
        return 0.0

    score = 0.0
    weights = {
        "is_known_legitimate": 0.4,
        "domain_age_days":     0.3,
        "has_mx_record":       0.15,
        "has_a_record":        0.15,
    }

    score += results["is_known_legitimate"] * weights["is_known_legitimate"]

    age = results["domain_age_days"]
    if age > 365:
        score += weights["domain_age_days"]
    elif age > 90:
        score += weights["domain_age_days"] * 0.5

    score += results["has_mx_record"] * weights["has_mx_record"]
    score += results["has_a_record"]  * weights["has_a_record"]

    if results["in_blacklist"]:
        return 0.0

    return round(score, 4)