import re
from urllib.parse import urlparse


SUSPICIOUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".php", ".js",
    ".bat", ".cmd", ".scr", ".vbs"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl",
    "ow.ly", "buff.ly", "short.link"
]


def analyze_structure(url: str) -> dict:
    parsed = urlparse(url)
    return {
        "url_length":           len(url),
        "has_port":             detect_port(parsed),
        "has_suspicious_ext":   detect_suspicious_extension(parsed.path),
        "is_shortened_url":     detect_shortened_url(parsed.netloc),
        "path_depth":           get_path_depth(parsed.path),
        "has_redirect":         detect_redirect(url),
        "digit_ratio_in_url":   get_digit_ratio(url),
        "special_char_count":   count_special_chars(url),
    }


def detect_port(parsed) -> int:
    return int(bool(parsed.port))


def detect_suspicious_extension(path: str) -> int:
    path_lower = path.lower()
    return int(any(path_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS))


def detect_shortened_url(netloc: str) -> int:
    netloc_lower = netloc.lower()
    return int(any(shortener in netloc_lower for shortener in SHORTENER_DOMAINS))


def get_path_depth(path: str) -> int:
    parts = [p for p in path.split("/") if p]
    return len(parts)


def detect_redirect(url: str) -> int:
    redirect_patterns = ["redirect", "url=", "link=", "goto=", "return="]
    url_lower = url.lower()
    return int(any(pattern in url_lower for pattern in redirect_patterns))


def get_digit_ratio(url: str) -> float:
    if not url:
        return 0.0
    digits = sum(1 for c in url if c.isdigit())
    return round(digits / len(url), 4)


def count_special_chars(url: str) -> int:
    special_chars = set("@-_~%+=[]{}|\\^`<>")
    return sum(1 for c in url if c in special_chars)