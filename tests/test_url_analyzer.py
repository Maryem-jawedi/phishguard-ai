import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.url_analyzer.url_parser import (
    parse_url, parse_urls,
    detect_ip_in_url, detect_obfuscation,
    count_suspicious_keywords, get_url_length_avg
)
from src.url_analyzer.structure_analyzer import (
    analyze_structure, detect_shortened_url,
    detect_suspicious_extension, get_path_depth, detect_redirect
)
from src.url_analyzer.feature_extractor import extract_url_features

# ══════════════════════════════════════════════════════════════════
# URLS DE TEST
# ══════════════════════════════════════════════════════════════════

# URLs phishing
URL_IP          = "http://192.168.1.100/login?verify=true"
URL_TK          = "http://paypal-secure-login.tk/verify?account=update"
URL_OBFUSCATED  = "http://paypal.com%40evil.com/steal"
URL_KEYWORDS    = "http://evil.com/secure/login/verify/account/confirm"
URL_SHORTENED   = "http://bit.ly/3xPhish"
URL_EXE         = "http://evil.com/malware/installer.exe"
URL_REDIRECT    = "http://evil.com/redirect?url=http://phish.com"

# URLs légitimes
URL_GOOGLE      = "https://www.google.com/search?q=test"
URL_GITHUB      = "https://github.com/user/repo"
URL_LEGIT_LONG  = "https://accounts.google.com/signin/v2/identifier?flowName=GlifWebSignIn"


# ══════════════════════════════════════════════════════════════════
# TESTS URL PARSER
# ══════════════════════════════════════════════════════════════════

def test_detect_ip_in_url():
    assert detect_ip_in_url(URL_IP) == 1,       "Doit détecter une IP dans l'URL"
    assert detect_ip_in_url(URL_GOOGLE) == 0,   "Ne doit pas détecter d'IP sur google.com"
    assert detect_ip_in_url(URL_TK) == 0,       "Pas d'IP dans cette URL .tk"
    print("✅ test_detect_ip_in_url passed")


def test_detect_obfuscation():
    assert detect_obfuscation(URL_OBFUSCATED) == 1, "Doit détecter l'obfuscation via %40"
    assert detect_obfuscation(URL_GOOGLE) == 0,     "Google ne doit pas être obfusqué"
    assert detect_obfuscation(URL_GITHUB) == 0,     "GitHub ne doit pas être obfusqué"
    print("✅ test_detect_obfuscation passed")


def test_count_suspicious_keywords():
    count = count_suspicious_keywords(URL_KEYWORDS)
    assert count >= 3, f"Doit détecter au moins 3 mots suspects, obtenu {count}"
    assert count_suspicious_keywords(URL_GITHUB) == 0, "GitHub n'a pas de mots suspects"
    print("✅ test_count_suspicious_keywords passed")


def test_get_url_length_avg():
    urls = [URL_IP, URL_GOOGLE, URL_TK]
    avg = get_url_length_avg(urls)
    expected = round(sum(len(u) for u in urls) / len(urls), 4)
    assert avg == expected, f"Moyenne incorrecte : {avg} != {expected}"
    assert get_url_length_avg([]) == 0.0, "Liste vide doit retourner 0.0"
    print("✅ test_get_url_length_avg passed")


def test_parse_url_structure():
    parsed = parse_url(URL_GOOGLE)
    assert parsed["scheme"] == "https",         "Scheme doit être https"
    assert parsed["domain"] == "google",        "Domaine doit être google"
    assert parsed["url_has_https"] == 1,        "url_has_https doit être 1"
    assert parsed["has_ip_in_url"] == 0,        "Pas d'IP dans google.com"
    assert parsed["url_length"] > 0,            "Longueur doit être > 0"
    print("✅ test_parse_url_structure passed")


def test_parse_urls_list():
    results = parse_urls([URL_IP, URL_GOOGLE, URL_TK])
    assert len(results) == 3,                   "Doit retourner 3 résultats"
    assert results[0]["has_ip_in_url"] == 1,    "Premier URL doit avoir IP"
    assert results[1]["url_has_https"] == 1,    "Google doit avoir HTTPS"
    print("✅ test_parse_urls_list passed")


# ══════════════════════════════════════════════════════════════════
# TESTS STRUCTURE ANALYZER
# ══════════════════════════════════════════════════════════════════

def test_detect_shortened_url():
    from urllib.parse import urlparse
    assert detect_shortened_url(urlparse(URL_SHORTENED).netloc) == 1, \
        "bit.ly doit être détecté comme URL raccourcie"
    assert detect_shortened_url(urlparse(URL_GOOGLE).netloc) == 0, \
        "google.com ne doit pas être raccourci"
    print("✅ test_detect_shortened_url passed")


def test_detect_suspicious_extension():
    from urllib.parse import urlparse
    assert detect_suspicious_extension(urlparse(URL_EXE).path) == 1, \
        ".exe doit être détecté comme extension suspecte"
    assert detect_suspicious_extension(urlparse(URL_GOOGLE).path) == 0, \
        "google.com n'a pas d'extension suspecte"
    print("✅ test_detect_suspicious_extension passed")


def test_get_path_depth():
    from urllib.parse import urlparse
    deep_url = "https://evil.com/level1/level2/level3/phish"
    assert get_path_depth(urlparse(deep_url).path) == 4,  "Doit avoir profondeur 4"
    assert get_path_depth(urlparse(URL_GOOGLE).path) == 1, "Google /search = profondeur 1"
    print("✅ test_get_path_depth passed")


def test_detect_redirect():
    assert detect_redirect(URL_REDIRECT) == 1,  "Doit détecter la redirection"
    assert detect_redirect(URL_GOOGLE) == 0,    "Google n'a pas de redirection"
    print("✅ test_detect_redirect passed")


def test_analyze_structure_complete():
    result = analyze_structure(URL_IP)
    assert "url_length" in result,          "url_length doit être présent"
    assert "has_port" in result,            "has_port doit être présent"
    assert "path_depth" in result,          "path_depth doit être présent"
    assert "digit_ratio_in_url" in result,  "digit_ratio_in_url doit être présent"
    assert result["url_length"] == len(URL_IP), "url_length doit correspondre"
    print("✅ test_analyze_structure_complete passed")


# ══════════════════════════════════════════════════════════════════
# TESTS FEATURE EXTRACTOR
# ══════════════════════════════════════════════════════════════════

def test_extract_url_features_phishing():
    features = extract_url_features([URL_IP])
    assert features["has_ip_in_url"] == 1,          "Doit détecter IP dans URL"
    assert features["url_has_https"] == 0,           "HTTP uniquement — pas HTTPS"
    assert features["url_count"] == 1,               "1 URL"
    print("✅ test_extract_url_features_phishing passed")


def test_extract_url_features_legit():
    features = extract_url_features([URL_GOOGLE])
    assert features["has_ip_in_url"] == 0,           "Pas d'IP dans google.com"
    assert features["url_has_https"] == 1,           "Google utilise HTTPS"
    assert features["url_obfuscated"] == 0,          "Pas d'obfuscation"
    print("✅ test_extract_url_features_legit passed")


def test_extract_url_features_empty():
    features = extract_url_features([])
    assert features["url_count"] == 0,               "0 URL → url_count = 0"
    assert features["url_length_avg"] == 0.0,        "0 URL → avg = 0.0"
    assert features["has_ip_in_url"] == 0,           "0 URL → pas d'IP"
    print("✅ test_extract_url_features_empty passed")


def test_extract_url_features_multiple():
    features = extract_url_features([URL_IP, URL_TK, URL_KEYWORDS])
    assert features["url_count"] == 3,               "3 URLs"
    assert features["has_ip_in_url"] == 1,           "Au moins une URL avec IP"
    assert features["suspicious_url_keywords"] >= 3, "Mots suspects cumulés"
    print("✅ test_extract_url_features_multiple passed")


# ══════════════════════════════════════════════════════════════════
# LANCEMENT
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n🚀 TESTS URL ANALYZER — PhishGuard AI\n")

    tests = [
        # Parser
        test_detect_ip_in_url,
        test_detect_obfuscation,
        test_count_suspicious_keywords,
        test_get_url_length_avg,
        test_parse_url_structure,
        test_parse_urls_list,
        # Structure
        test_detect_shortened_url,
        test_detect_suspicious_extension,
        test_get_path_depth,
        test_detect_redirect,
        test_analyze_structure_complete,
        # Feature extractor
        test_extract_url_features_phishing,
        test_extract_url_features_legit,
        test_extract_url_features_empty,
        test_extract_url_features_multiple,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"❌ {test.__name__} FAILED — {e}")
            failed += 1
        except Exception as e:
            print(f"💥 {test.__name__} ERROR — {e}")
            failed += 1

    print(f"\n{'═'*50}")
    print(f"  RÉSUMÉ : {passed}/{passed+failed} tests réussis")
    if failed == 0:
        print("  🏆 TOUS LES TESTS SONT PASSÉS !")
    else:
        print(f"  ⚠️  {failed} test(s) ont échoué")
    print(f"{'═'*50}")