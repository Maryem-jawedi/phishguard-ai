from src.email_analyzer.parser import ParsedEmail
from src.email_analyzer.nlp_analyzer import analyze_text
from src.email_analyzer.auth_verifier import verify_auth
from src.url_analyzer.url_parser import parse_urls, get_url_length_avg

TLDS_SUSPECTS = ['.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc']

SUSPICIOUS_WORDS = [
    "secure", "verify", "login", "update", "account",
    "banking", "paypal", "amazon", "apple", "microsoft"
]

KNOWN_BRANDS = {
    "paypal":    "paypal.com",
    "amazon":    "amazon.com",
    "apple":     "apple.com",
    "google":    "google.com",
    "microsoft": "microsoft.com",
    "netflix":   "netflix.com",
}


def extract_features(parsed_email: ParsedEmail) -> dict:
    """
    Reçoit un ParsedEmail et retourne le vecteur de features complet
    conforme au features_contract.json (22 features numériques + réseau).
    """

    # -- groupe 1 : features textuelles (9 features dont has_url)
    text_features = analyze_text(
        subject=parsed_email.subject,
        body=parsed_email.body,
        html_content=parsed_email.html_content
    )

    # -- groupe 2 : features URL (8 features)
    parsed_urls = parse_urls(parsed_email.urls)
    url_features = _extract_url_features(parsed_email.urls, parsed_urls)

    # -- groupe 3 : features expéditeur (4 features numériques — sender_domain retiré)
    sender_features = _extract_sender_features(
        sender_name=parsed_email.sender_name,
        sender_email=parsed_email.sender_email
    )

    # -- groupe 4 : features réseau (7 features)
    domain = parsed_email.sender_email.split("@")[-1] if "@" in parsed_email.sender_email else ""
    network_features = verify_auth(
        sender_email=parsed_email.sender_email,
        domain=domain
    )

    features = {
        **text_features,
        **url_features,
        **sender_features,
        **network_features,
    }

    return features


def _extract_url_features(urls: list[str], parsed_urls: list[dict]) -> dict:
    if not parsed_urls:
        return {
            "url_count":                0,
            "url_length_avg":           0.0,
            "has_ip_in_url":            0,
            "url_obfuscated":           0,
            "subdomain_count":          0,
            "suspicious_url_keywords":  0,
            "url_has_https":            0,
            "url_tld_suspect":          0,   # AJOUT
        }

    return {
        "url_count":               len(urls),
        "url_length_avg":          get_url_length_avg(urls),
        "has_ip_in_url":           int(any(u["has_ip_in_url"] for u in parsed_urls)),
        "url_obfuscated":          int(any(u["url_obfuscated"] for u in parsed_urls)),
        "subdomain_count":         max(u["subdomain_count"] for u in parsed_urls),
        "suspicious_url_keywords": sum(u["suspicious_url_keywords"] for u in parsed_urls),
        "url_has_https":           int(all(u["url_has_https"] for u in parsed_urls)),
        "url_tld_suspect":         int(                                 # AJOUT
            any(url.lower().endswith(t) or
                any(f"{t}/" in url.lower() for _ in [0])
                for url in urls for t in TLDS_SUSPECTS)
        ),
    }


def _extract_sender_features(sender_name: str, sender_email: str) -> dict:
    domain = sender_email.split("@")[-1] if "@" in sender_email else ""

    return {
        # sender_domain (string) retiré du vecteur numérique
        "sender_domain_length":     len(domain),
        "sender_has_numbers":       int(any(c.isdigit() for c in domain)),
        "sender_domain_suspicious": _is_domain_suspicious(domain),
        "sender_tld_suspect":       int(any(domain.endswith(t) for t in TLDS_SUSPECTS)),  # AJOUT
        "display_name_mismatch":    _detect_display_name_mismatch(sender_name, domain),
    }


def _is_domain_suspicious(domain: str) -> int:
    domain_lower = domain.lower()
    return int(any(word in domain_lower for word in SUSPICIOUS_WORDS))


def _detect_display_name_mismatch(sender_name: str, domain: str) -> int:
    name_lower = sender_name.lower()
    for brand, legit_domain in KNOWN_BRANDS.items():
        if brand in name_lower and legit_domain not in domain:
            return 1
    return 0