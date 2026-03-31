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


def verify_auth(sender_email: str, domain: str) -> dict:
    return {
        "spf_valid":             check_spf(domain),
        "dkim_valid":            check_dkim(domain),
        "dmarc_valid":           check_dmarc(domain),
        "domain_age_days":       get_domain_age(domain),
        "ssl_valid":             check_ssl(domain),
        "in_blacklist":          check_blacklist(domain),
        "sender_ip_reputation":  check_ip_reputation(sender_email),
    }


def check_spf(domain: str) -> int:
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for record in answers:
            if "v=spf1" in str(record):
                return 1
        return 0
    except Exception:
        return 0


def check_dkim(domain: str) -> int:
    try:
        dkim_domain = f"default._domainkey.{domain}"
        answers = dns.resolver.resolve(dkim_domain, "TXT")
        for record in answers:
            if "v=DKIM1" in str(record):
                return 1
        return 0
    except Exception:
        return 0


def check_dmarc(domain: str) -> int:
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for record in answers:
            if "v=DMARC1" in str(record):
                return 1
        return 0
    except Exception:
        return 0


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


def check_ssl(domain: str) -> int:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                return 1
    except Exception:
        return 0


def check_blacklist(domain: str) -> int:
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find"
        # placeholder — à connecter avec Google Safe Browsing API key
        # pour l'instant retourne 0 par défaut
        return 0
    except Exception:
        return 0


def check_ip_reputation(sender_email: str) -> int:
    try:
        domain = sender_email.split("@")[-1]
        ip = socket.gethostbyname(domain)
        # placeholder — à connecter avec AbuseIPDB API key
        # pour l'instant retourne 0 par défaut
        return 0
    except Exception:
        return 0