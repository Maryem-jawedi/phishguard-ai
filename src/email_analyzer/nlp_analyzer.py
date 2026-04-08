import re

URGENCY_WORDS = [
    "urgent", "immediately", "verify", "confirm", "click", "suspend",
    "limited", "expire", "warning", "alert", "action required",
    "your account", "unusual activity", "login", "password", "update now",
    "winner", "congratulations", "free", "prize", "claim"
]

SUSPICIOUS_HTML_TAGS = ["script", "iframe", "form", "input", "object"]


def analyze_text(subject: str, body: str, html_content: str) -> dict:
    return {
        "subject_length":    get_subject_length(subject),
        "body_length":       get_body_length(body),
        "word_count":        get_word_count(body),
        "urgency_score":     get_urgency_score(body),
        "caps_ratio":        get_caps_ratio(subject),
        "has_url":           get_has_url(body, html_content),   # AJOUT
        "exclamation_count": get_exclamation_count(body),
        "question_count":    get_question_count(body),
        "html_tags_count":   get_html_tags_count(html_content),
    }


def get_subject_length(subject: str) -> int:
    return len(subject)


def get_body_length(body: str) -> int:
    return len(body)


def get_word_count(body: str) -> int:
    return len(body.split())


def get_urgency_score(body: str) -> float:
    body_lower = body.lower()
    count = sum(1 for word in URGENCY_WORDS if word in body_lower)
    return round(min(count / len(URGENCY_WORDS), 1.0), 4)


def get_caps_ratio(subject: str) -> float:
    if not subject:
        return 0.0
    letters = [c for c in subject if c.isalpha()]
    if not letters:
        return 0.0
    caps = sum(1 for c in letters if c.isupper())
    return round(caps / len(letters), 4)


def get_has_url(body: str, html_content: str) -> int:
    """Détecte la présence d'au moins une URL dans le corps ou le HTML."""
    combined = (body + " " + html_content).lower()
    return int("http://" in combined or "https://" in combined)


def get_exclamation_count(body: str) -> int:
    return body.count("!")


def get_question_count(body: str) -> int:
    return body.count("?")


def get_html_tags_count(html_content: str) -> int:
    tags = re.findall(r'<[^>]+>', html_content)
    return len(tags)