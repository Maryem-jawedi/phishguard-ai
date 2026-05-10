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
    """
    Retourne les features réseau.

    IMPORTANT — convention des valeurs de retour :
        1    = vérification réussie (valide)
        0    = vérification effectuée mais invalide
        None = vérification impossible (timeout, erreur DNS, domaine inconnu)

    Cette distinction est critique pour le predictor :
    un None ne doit PAS pénaliser un email légitime dont le DNS
    est simplement inaccessible depuis la machine d'analyse.
    """
    return {
        "spf_valid"           : check_spf(domain),
        "dkim_valid"          : check_dkim(domain, headers),
        "dmarc_valid"         : check_dmarc(domain),
        "domain_age_days"     : get_domain_age(domain),
        "ssl_valid"           : check_ssl(domain),
        "in_blacklist"        : check_blacklist(domain),
        "sender_ip_reputation": check_ip_reputation(sender_email),
    }


def _make_resolver() -> dns.resolver.Resolver:
    """Crée un resolver DNS avec timeout court pour éviter les blocages."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout  = DNS_TIMEOUT
    return resolver


def check_spf(domain: str):
    """
    Retourne :
        1    → enregistrement SPF trouvé et valide
        0    → enregistrement TXT résolu mais pas de SPF
        None → timeout DNS ou domaine inaccessible
    """
    if not domain or domain == "unknown":
        return None
    try:
        resolver = _make_resolver()
        answers = resolver.resolve(domain, "TXT")
        for record in answers:
            if "v=spf1" in str(record):
                return 1
        return 0  # TXT résolu mais pas de SPF → domaine existe, SPF absent
    except dns.resolver.NXDOMAIN:
        return 0   # domaine inexistant → suspect
    except dns.resolver.NoAnswer:
        return 0   # pas de TXT du tout
    except Exception:
        # timeout, NoNameservers, etc. → on ne peut pas conclure
        return None


def check_dkim(domain: str, headers: dict = None):
    """
    Extrait le vrai sélecteur DKIM depuis les headers si disponibles.
    Limite à 4 sélecteurs courants en fallback pour éviter les timeouts.

    Retourne :
        1    → enregistrement DKIM1 trouvé
        0    → aucun sélecteur ne répond avec DKIM1
        None → tous les essais ont échoué par timeout
    """
    if not domain or domain == "unknown":
        return None

    selectors_to_try = []

    if headers:
        dkim_header = headers.get("DKIM-Signature", "") or headers.get("dkim-signature", "")
        if dkim_header:
            match = re.search(r'\bs=([^;]+)', dkim_header)
            if match:
                selectors_to_try.append(match.group(1).strip())

    selectors_to_try += ["default", "google", "selector1", "mail"]

    all_timeout = True
    for selector in selectors_to_try:
        try:
            resolver = _make_resolver()
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = resolver.resolve(dkim_domain, "TXT")
            all_timeout = False  # au moins une réponse obtenue
            for record in answers:
                if "v=DKIM1" in str(record):
                    return 1
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            all_timeout = False  # réponse DNS reçue (négative)
            continue
        except Exception:
            continue  # timeout — on continue avec le sélecteur suivant

    # Si tous les essais ont timeout → indéterminé
    if all_timeout:
        return None

    return 0  # DNS accessible mais pas de DKIM trouvé


def check_dmarc(domain: str):
    """
    Retourne :
        1    → enregistrement DMARC1 trouvé
        0    → DNS accessible mais pas de DMARC
        None → timeout / inaccessible
    """
    if not domain or domain == "unknown":
        return None
    try:
        resolver = _make_resolver()
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, "TXT")
        for record in answers:
            if "v=DMARC1" in str(record):
                return 1
        return 0
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return 0
    except Exception:
        return None


def get_domain_age(domain: str) -> int:
    """
    Retourne l'âge du domaine en jours, ou -1 si WHOIS inaccessible.
    -1 n'est PAS traité comme suspect par le predictor.
    """
    if not domain or domain == "unknown":
        return -1
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


def check_ssl(domain: str):
    """
    Retourne :
        1    → certificat SSL valide
        0    → connexion échoue (pas de HTTPS ou cert invalide)
        None → timeout de connexion (on ne peut pas conclure)
    """
    if not domain or domain == "unknown":
        return None
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                ssock.getpeercert()
                return 1
    except ssl.SSLError:
        return 0   # connexion établie mais cert invalide → suspect
    except (ConnectionRefusedError, OSError):
        return 0   # port 443 fermé ou domaine inconnu → pas de HTTPS
    except Exception:
        # TimeoutError, etc. → on ne peut pas conclure
        return None


def check_blacklist(domain: str) -> int:
    """
    Placeholder — à connecter avec Google Safe Browsing API.
    Retourne toujours 0 (non listé) jusqu'à intégration réelle.
    """
    try:
        return 0
    except Exception:
        return 0


def check_ip_reputation(sender_email: str) -> int:
    """
    Placeholder — à connecter avec AbuseIPDB.
    Retourne toujours 0 (réputation neutre) jusqu'à intégration réelle.
    """
    try:
        domain = sender_email.split("@")[-1] if "@" in sender_email else ""
        if not domain:
            return 0
        socket.setdefaulttimeout(3)
        ip = socket.gethostbyname(domain)
        socket.setdefaulttimeout(None)
        return 0
    except Exception:
        return 0