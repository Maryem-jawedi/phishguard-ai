import sys
import os
import requests
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ══════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════
API_BASE   = "http://127.0.0.1:8000"
API_EMAIL  = f"{API_BASE}/api/v1/analyze/email"
API_URL    = f"{API_BASE}/api/v1/analyze/url"
API_HEALTH = f"{API_BASE}/health"

TIMEOUT = 60


def get_token():
    response = requests.post(
        f"{API_BASE}/api/v1/auth/token",
        data={"username": "analyst", "password": "analyst123"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    print("DEBUG token:", response.text)
    return response.json()["access_token"]


TOKEN = get_token()
# ✅ Headers avec JWT — passés à CHAQUE requête
HEADERS = {"Authorization": f"Bearer {TOKEN}"}


# ══════════════════════════════════════════════════════════════════
# EMAILS DE TEST
# ══════════════════════════════════════════════════════════════════

EMAIL_PHISHING = """From: "PayPal Security" <security@paypal-alert-update.xyz>
Subject: URGENT!!! Your PayPal account has been SUSPENDED
Content-Type: text/plain

Dear Customer,
WARNING: Unusual activity detected on your account!
Your account will be permanently suspended in 24 hours.
Click here immediately: http://paypal-secure-login.xyz/verify?account=update
This is your FINAL WARNING!!!
"""

EMAIL_LEGITIME = """From: "Alice Martin" <alice.martin@gmail.com>
Subject: Reunion de demain
Content-Type: text/plain

Bonjour,
Je voulais confirmer notre reunion de demain a 10h.
A demain,
Alice
"""

EMAIL_MALFORMED = """From: broken-email-no-subject
"""


# ══════════════════════════════════════════════════════════════════
# HELPER
# ══════════════════════════════════════════════════════════════════

def check_api_available() -> bool:
    try:
        r = requests.get(API_HEALTH, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════
# TESTS HEALTH
# ══════════════════════════════════════════════════════════════════

def test_health_endpoint():
    r = requests.get(API_HEALTH, timeout=5)
    assert r.status_code == 200, "Health endpoint doit retourner 200"
    data = r.json()
    assert data["status"] == "ok", "Status doit être 'ok'"
    assert "version" in data, "Version doit être présente"
    print("✅ test_health_endpoint passed")


# ══════════════════════════════════════════════════════════════════
# TESTS EMAIL
# ══════════════════════════════════════════════════════════════════

def test_email_phishing_detected():
    r = requests.post(API_EMAIL, json={"raw_email": EMAIL_PHISHING},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code == 200, "Doit retourner 200"
    data = r.json()
    assert "is_phishing" in data,         "is_phishing doit être présent"
    assert "confidence" in data,          "confidence doit être présent"
    assert "features" in data,            "features doit être présent"
    assert "suspicious_elements" in data, "suspicious_elements doit être présent"
    assert "report" in data,              "report doit être présent"
    assert data["is_phishing"] == 1,      "Doit être classé PHISHING"
    assert data["confidence"] >= 50,      "Confiance doit être >= 50%"
    assert len(data["suspicious_elements"]) > 0, "Doit avoir des éléments suspects"
    print(f"✅ test_email_phishing_detected passed — confiance : {data['confidence']}%")


def test_email_legitime_detected():
    r = requests.post(API_EMAIL, json={"raw_email": EMAIL_LEGITIME},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code == 200, "Doit retourner 200"
    data = r.json()
    assert "is_phishing" in data,            "Champ is_phishing présent"
    assert "confidence" in data,             "Champ confidence présent"
    assert "features" in data,               "Champ features présent"
    assert "suspicious_elements" in data,    "Champ suspicious_elements présent"
    assert "report" in data,                 "Champ report présent"
    assert isinstance(data["is_phishing"], int),   "is_phishing doit être un entier"
    assert isinstance(data["confidence"], float),  "confidence doit être un float"
    assert 0 <= data["confidence"] <= 100,         "confidence doit être dans [0, 100]"
    f = data["features"]
    assert f.get("has_ip_in_url", 0) == 0,         "Pas d'IP dans cet email"
    assert f.get("url_tld_suspect", 0) == 0,        "Pas de TLD suspect"
    assert f.get("display_name_mismatch", 0) == 0,  "Pas de mismatch nom/domaine"
    assert f.get("url_count", 0) == 0,              "Aucune URL dans cet email"
    print(f"✅ test_email_legitime_detected passed — confiance : {data['confidence']}%")


def test_email_response_schema():
    r = requests.post(API_EMAIL, json={"raw_email": EMAIL_PHISHING},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    data = r.json()
    required_fields = ["is_phishing", "confidence", "features", "suspicious_elements", "report"]
    for field in required_fields:
        assert field in data, f"Champ manquant dans la réponse : {field}"
    features = data["features"]
    expected_features = [
        "subject_length", "body_length", "urgency_score",
        "url_count", "has_ip_in_url", "spf_valid", "dkim_valid"
    ]
    for f in expected_features:
        assert f in features, f"Feature manquante : {f}"
    print("✅ test_email_response_schema passed")


def test_email_malformed():
    r = requests.post(API_EMAIL, json={"raw_email": EMAIL_MALFORMED},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code in [200, 500], "Doit retourner 200 ou 500, pas autre chose"
    print("✅ test_email_malformed passed — API ne crashe pas")


def test_email_empty():
    r = requests.post(API_EMAIL, json={"raw_email": ""},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code in [200, 500], "Doit retourner 200 ou 500"
    print("✅ test_email_empty passed — API ne crashe pas")


def test_email_confidence_range():
    for raw in [EMAIL_PHISHING, EMAIL_LEGITIME]:
        r = requests.post(API_EMAIL, json={"raw_email": raw},
                          headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
        data = r.json()
        conf = data["confidence"]
        assert 0 <= conf <= 100, f"Confiance hors bornes : {conf}"
    print("✅ test_email_confidence_range passed")


def test_email_report_not_empty():
    r = requests.post(API_EMAIL, json={"raw_email": EMAIL_PHISHING},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    data = r.json()
    assert data["report"] and len(data["report"]) > 10, "Rapport ne doit pas être vide"
    print("✅ test_email_report_not_empty passed")


# ══════════════════════════════════════════════════════════════════
# TESTS URL
# ══════════════════════════════════════════════════════════════════

def test_url_phishing_ip():
    r = requests.post(API_URL, json={"url": "http://192.168.1.1/login"},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code == 200, "Doit retourner 200"
    data = r.json()
    assert "is_phishing" in data,                  "is_phishing doit être présent"
    assert "url" in data,                          "url doit être présent dans la réponse"
    assert data["features"]["has_ip_in_url"] == 1, "Doit détecter IP dans URL"
    print(f"✅ test_url_phishing_ip passed — is_phishing : {data['is_phishing']}")


def test_url_phishing_tld():
    r = requests.post(API_URL, json={"url": "http://paypal-verify.tk/login"},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code == 200, "Doit retourner 200"
    data = r.json()
    assert data["features"]["url_tld_suspect"] == 1, "Doit détecter TLD suspect .tk"
    print("✅ test_url_phishing_tld passed")


def test_url_legitime():
    r = requests.post(API_URL, json={"url": "https://www.google.com"},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    assert r.status_code == 200, "Doit retourner 200"
    data = r.json()
    assert data["features"]["url_has_https"] == 1, "Google doit avoir HTTPS"
    assert data["features"]["has_ip_in_url"] == 0, "Pas d'IP dans google.com"
    print("✅ test_url_legitime passed")


def test_url_response_schema():
    r = requests.post(API_URL, json={"url": "http://test.tk/verify"},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    data = r.json()
    required_fields = ["url", "is_phishing", "confidence", "features", "suspicious_elements"]
    for field in required_fields:
        assert field in data, f"Champ manquant : {field}"
    print("✅ test_url_response_schema passed")


def test_url_echo():
    url = "https://example.com/test"
    r = requests.post(API_URL, json={"url": url},
                      headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    data = r.json()
    assert data["url"] == url, f"URL retournée incorrecte : {data['url']}"
    print("✅ test_url_echo passed")


# ══════════════════════════════════════════════════════════════════
# TESTS PERFORMANCE
# ══════════════════════════════════════════════════════════════════

def test_response_time_email():
    start = time.time()
    requests.post(API_EMAIL, json={"raw_email": EMAIL_PHISHING},
                  headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    elapsed = time.time() - start
    assert elapsed < 30, f"Trop lent : {elapsed:.1f}s (max 30s)"
    print(f"✅ test_response_time_email passed — {elapsed:.2f}s")


def test_response_time_url():
    start = time.time()
    requests.post(API_URL, json={"url": "https://www.google.com"},
                  headers=HEADERS, timeout=TIMEOUT)  # ✅ JWT
    elapsed = time.time() - start
    assert elapsed < 30, f"Trop lent : {elapsed:.1f}s (max 30s)"
    print(f"✅ test_response_time_url passed — {elapsed:.2f}s")


# ══════════════════════════════════════════════════════════════════
# LANCEMENT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n🚀 TESTS D'INTÉGRATION — PhishGuard AI\n")

    if not check_api_available():
        print("❌ L'API FastAPI n'est pas accessible sur http://127.0.0.1:8000")
        print("   Lance d'abord : uvicorn src.api.main:app --reload --port 8000")
        sys.exit(1)

    print("✅ API disponible — lancement des tests\n")

    tests = [
        ("Health endpoint",        test_health_endpoint),
        ("Email phishing détecté", test_email_phishing_detected),
        ("Email légitime détecté", test_email_legitime_detected),
        ("Email schéma réponse",   test_email_response_schema),
        ("Email malformé",         test_email_malformed),
        ("Email vide",             test_email_empty),
        ("Confiance dans [0,100]", test_email_confidence_range),
        ("Rapport non vide",       test_email_report_not_empty),
        ("URL avec IP",            test_url_phishing_ip),
        ("URL TLD suspect",        test_url_phishing_tld),
        ("URL légitime",           test_url_legitime),
        ("URL schéma réponse",     test_url_response_schema),
        ("URL echo",               test_url_echo),
        ("Temps réponse email",    test_response_time_email),
        ("Temps réponse URL",      test_response_time_url),
    ]

    passed = 0
    failed = 0

    for name, test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"❌ {name} FAILED — {e}")
            failed += 1
        except Exception as e:
            print(f"💥 {name} ERROR — {type(e).__name__}: {e}")
            failed += 1

    print(f"\n{'═'*55}")
    print(f"  RÉSUMÉ FINAL")
    print(f"{'═'*55}")
    print(f"  Tests réussis  : {passed}/{passed+failed}")
    print(f"  Taux de succès : {passed/(passed+failed)*100:.0f}%")
    if failed == 0:
        print("  🏆 TOUS LES TESTS D'INTÉGRATION SONT PASSÉS !")
    else:
        print(f"  ⚠️  {failed} test(s) ont échoué")
    print(f"{'═'*55}")