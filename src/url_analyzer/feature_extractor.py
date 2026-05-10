from src.url_analyzer.url_parser import parse_urls, get_url_length_avg
from src.url_analyzer.structure_analyzer import analyze_structure
from src.url_analyzer.reputation_checker import get_domain_reputation_score
import tldextract
from urllib.parse import urlparse

TLDS_SUSPECTS = ['.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.pw', '.cc']


def extract_url_features(urls: list[str]) -> dict:
    if not urls:
        return _empty_url_features()

    # -- parsing de toutes les URLs
    parsed_urls = parse_urls(urls)

    # -- analyse de structure de toutes les URLs
    structures = [analyze_structure(url) for url in urls]

    # -- réputation du domaine principal (première URL) — protégé contre les crashes
    try:
        main_domain = _get_main_domain(urls[0])
        reputation_score = get_domain_reputation_score(main_domain) if main_domain != "unknown" else 0.0
    except Exception:
        reputation_score = 0.0

    return {
        "url_count":               len(urls),
        "url_length_avg":          get_url_length_avg(urls),
        "has_ip_in_url":           int(any(u["has_ip_in_url"] for u in parsed_urls)),
        "url_obfuscated":          int(any(u["url_obfuscated"] for u in parsed_urls)),
        "subdomain_count":         max(u["subdomain_count"] for u in parsed_urls),
        "suspicious_url_keywords": sum(u["suspicious_url_keywords"] for u in parsed_urls),
        "url_has_https":           int(all(u["url_has_https"] for u in parsed_urls)),
        "domain_reputation":       reputation_score,
        "has_shortened_url":       int(any(s["is_shortened_url"] for s in structures)),
        "has_suspicious_ext":      int(any(s["has_suspicious_ext"] for s in structures)),
        "max_path_depth":          max(s["path_depth"] for s in structures),
        "has_redirect":            int(any(s["has_redirect"] for s in structures)),
        "avg_digit_ratio":         round(
                                       sum(s["digit_ratio_in_url"] for s in structures) / len(structures),
                                       4
                                   ),
        "avg_special_char_count":  round(
                                       sum(s["special_char_count"] for s in structures) / len(structures),
                                       4
                                   ),
        "url_tld_suspect":         int(any(
                                       url.lower().endswith(t) or f"{t}/" in url.lower()
                                       for url in urls for t in TLDS_SUSPECTS
                                   )),
    }


def _get_main_domain(url: str) -> str:
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain
        suffix = extracted.suffix
        if not domain or not suffix:
            # Fallback : extraire le hostname manuellement
            parsed = urlparse(url)
            hostname = parsed.netloc.split(":")[0]
            return hostname if hostname else "unknown"
        return f"{domain}.{suffix}"
    except Exception:
        return "unknown"


def _empty_url_features() -> dict:
    return {
        "url_count":               0,
        "url_length_avg":          0.0,
        "has_ip_in_url":           0,
        "url_obfuscated":          0,
        "subdomain_count":         0,
        "suspicious_url_keywords": 0,
        "url_has_https":           0,
        "domain_reputation":       0.0,
        "has_shortened_url":       0,
        "has_suspicious_ext":      0,
        "max_path_depth":          0,
        "has_redirect":            0,
        "avg_digit_ratio":         0.0,
        "avg_special_char_count":  0.0,
        "url_tld_suspect":         0,
    }