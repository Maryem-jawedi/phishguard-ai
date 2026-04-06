import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.email_analyzer.parser import parse_email
from src.email_analyzer.nlp_analyzer import analyze_text
from src.email_analyzer.feature_extractor import extract_features


SAMPLE_PHISHING_EMAIL = """From: "PayPal Support" <support@paypal-secure-login.com>
Subject: URGENT: Verify your account immediately!!!
Content-Type: text/plain

Dear Customer,
Your account has been suspended! Click here to verify immediately:
http://192.168.1.1/login
http://paypal-secure.evil.com/verify?update=true
Please confirm your password and login details urgently!!!???
"""


def test_parse_email():
    parsed = parse_email(SAMPLE_PHISHING_EMAIL)
    assert parsed.subject == "URGENT: Verify your account immediately!!!"
    assert parsed.sender_email == "support@paypal-secure-login.com"
    assert parsed.sender_name == "PayPal Support"
    assert len(parsed.urls) == 2
    print("✅ test_parse_email passed")


def test_nlp_features():
    parsed = parse_email(SAMPLE_PHISHING_EMAIL)
    features = analyze_text(parsed.subject, parsed.body, parsed.html_content)
    assert features["subject_length"] > 0
    assert features["urgency_score"] > 0
    assert features["exclamation_count"] >= 3
    assert features["question_count"] >= 1
    print("✅ test_nlp_features passed")


def test_extract_features():
    parsed = parse_email(SAMPLE_PHISHING_EMAIL)
    features = extract_features(parsed)
    assert "subject_length" in features
    assert "url_count" in features
    assert "spf_valid" in features
    assert "sender_domain" in features
    assert features["url_count"] == 2
    assert features["display_name_mismatch"] == 1
    print("✅ test_extract_features passed")


if __name__ == "__main__":
    test_parse_email()
    test_nlp_features()
    test_extract_features()
    print("\n✅ Tous les tests sont passés !")