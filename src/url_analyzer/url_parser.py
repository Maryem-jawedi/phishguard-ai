import re
import tldextract
from urllib.parse import urlparse, parse_qs

SUSPICIOUS_KEYWORDS = [
    "verify", "login", "secure", "update", "account",
    "banking", "confirm", "password", "signin", "webscr"
]

OBFUSCATION_PATTERNS = ["@", "//", "%20", "%40", "0x"]


def parse_url(url: str) -> dict:
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    return {
        "raw_url":          url,
        "scheme":           parsed.scheme,
        "domain":           extracted.domain,
        "suffix":           extracted.suffix,
        "subdomain":        extracted.subdomain,
        "path":             parsed.path,
        "params":           parse_qs(parsed.query),
        "url_length":       len(url),
        "subdomain_count":  get_subdomain_count(extracted.subdomain),
        "has_ip_in_url":    detect_ip_in_url(url),
        "url_obfuscated":   detect_obfuscation(url),
        "url_has_https":    int(parsed.scheme == "https"),
        "suspicious_url_keywords": count_suspicious_keywords(url),
    }


def parse_urls(urls: list[str]) -> list[dict]:
    return [parse_url(url) for url in urls]


def get_subdomain_count(subdomain: str) -> int:
    if not subdomain:
        return 0
    return len(subdomain.split("."))


def detect_ip_in_url(url: str) -> int:
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    return int(bool(re.search(ip_pattern, url)))


def detect_obfuscation(url: str) -> int:
    for pattern in OBFUSCATION_PATTERNS:
        if pattern in url:
            return 1
    return 0


def count_suspicious_keywords(url: str) -> int:
    url_lower = url.lower()
    return sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)


def get_url_length_avg(urls: list[str]) -> float:
    if not urls:
        return 0.0
    return round(sum(len(url) for url in urls) / len(urls), 4)