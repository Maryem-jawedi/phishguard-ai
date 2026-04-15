import re
import dns.resolver
import ssl
import socket
import requests
from datetime import datetime
import whois

SUSPICIOUS_DOMAIN_KEYWORDS = [
    "secure", "verify", "login", "update", "account",
    "banking", "paypal", "amazon", "apple", "microsoft"
]

# Timeout global pour toutes les résolutions DNS (secondes)
DNS_TIMEOUT = 3


def verify_auth(sender_email: str, domain: str, headers: dict = None) -> dict:
    return {
        "spf_valid":            check_spf(domain),
        "dkim_valid":           check_dkim(domain, headers),
        "dmarc_valid":          check_dmarc(domain),
        "domain_age_days":      get_domain_age(domain),
        "ssl_valid":            check_ssl(domain),
        "in_blacklist":         check_blacklist(domain),
        "sender_ip_reputation": check_ip_reputation(sender_email),
    }


def _make_resolver() -> dns.resolver.Resolver:
    """Crée un resolver DNS avec timeout court pour éviter les blocages."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout  = DNS_TIMEOUT
    return resolver


def check_spf(domain: str) -> int:
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "TXT")
        for record in answers:
            if "v=spf1" in str(record):
                return 1
        return 0
    except Exception:
        return 0


def check_dkim(domain: str, headers: dict = None) -> int:
    """
    Extrait le vrai sélecteur DKIM depuis les headers si disponibles.
    Limite à 4 sélecteurs courants en fallback pour éviter les timeouts.
    """
    selectors_to_try = []

    # 1. Sélecteur extrait du header DKIM-Signature
    if headers:
        dkim_header = headers.get("DKIM-Signature", "") or headers.get("dkim-signature", "")
        if dkim_header:
            match = re.search(r'\bs=([^;]+)', dkim_header)
            if match:
                selectors_to_try.append(match.group(1).strip())

    # 2. Sélecteurs courants — limités à 4 pour rester sous 12s au total
    selectors_to_try += ["default", "google", "selector1", "mail"]

    for selector in selectors_to_try:
        try:
            resolver = _make_resolver()
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")
            for record in answers:
                if "v=DKIM1" in str(record):
                    return 1
        except Exception:
            continue

    return 0


def check_dmarc(domain: str) -> int:
    try:
        resolver = _make_resolver()
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for record in answers:
            if "v=DMARC1" in str(record):
                return 1
        return 0
    except Exception:
        return 0


def get_domain_age(domain: str) -> int:
    try:
        # Timeout whois via signal non disponible sur Windows
        # On utilise un try/except avec un délai raisonnable
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


def check_ssl(domain: str) -> int:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                return 1
    except Exception:
        return 0


def check_blacklist(domain: str) -> int:
    try:
        # Placeholder — à connecter avec Google Safe Browsing API
        return 0
    except Exception:
        return 0


def check_ip_reputation(sender_email: str) -> int:
    try:
        domain = sender_email.split("@")[-1]
        socket.setdefaulttimeout(3)
        ip = socket.gethostbyname(domain)
        socket.setdefaulttimeout(None)
        # Placeholder — à connecter avec AbuseIPDB
        return 0
    except Exception:
        return 0