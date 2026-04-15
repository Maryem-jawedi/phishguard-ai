import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.email_analyzer.parser import parse_email
from src.email_analyzer.feature_extractor import extract_features
from src.ml_engine.predictor import PhishingPredictor

predictor = PhishingPredictor()

# ══════════════════════════════════════════════════════════════════
# EMAILS DE TEST
# ══════════════════════════════════════════════════════════════════

EMAIL_PHISHING_IP = """From: "Google Team" <noreply@google-secure-verify.tk>
Subject: Action required: Verify your Google account
Content-Type: text/plain

Your Google account will be suspended in 24 hours.
Please verify immediately:
http://google-account-verify.tk/login?confirm=true
"""

EMAIL_PHISHING_URGENT = """From: "PayPal Security" <security@paypal-alert-update.xyz>
Subject: URGENT!!! Your PayPal account has been SUSPENDED
Content-Type: text/plain

Dear Customer,

WARNING: Unusual activity has been detected on your account!
Your account has been limited. You must confirm your identity immediately
or your account will be permanently suspended.

Click here NOW to verify your password and login:
http://paypal-secure-login.xyz/verify?account=update&confirm=true

This is your FINAL WARNING. Act immediately!
Do not ignore this alert!!!
"""

EMAIL_PHISHING_GOOGLE = """From: "Google Support" <no-reply@google-accounts-verify.ml>
Subject: Your Google account access will expire
Content-Type: text/plain

Hello,

We detected a suspicious login attempt on your Google account.
To secure your account, please verify your identity immediately:

http://google-accounts-verify.ml/secure/login?update=true&session=expired

If you do not verify within 24 hours, your account will be suspended.
Enter your password and confirm your details urgently.

Google Security Team
"""

EMAIL_LEGITIME_SIMPLE = """From: "Alice Martin" <alice.martin@gmail.com>
Subject: Reunion de demain
Content-Type: text/plain

Bonjour,

Je voulais te rappeler qu'on a une reunion demain a 10h dans la salle B.
N'oublie pas d'apporter le rapport de la semaine derniere.

A demain,
Alice
"""

EMAIL_LEGITIME_PRO = """From: "Service RH" <rh@entreprise.fr>
Subject: Votre bulletin de salaire - Mars 2026
Content-Type: text/plain

Bonjour,

Veuillez trouver ci-joint votre bulletin de salaire pour le mois de mars 2026.
Pour toute question, n'hesitez pas a contacter le service RH.

Cordialement,
Le Service des Ressources Humaines
entreprise.fr
"""

# ══════════════════════════════════════════════════════════════════
# FONCTION D'AFFICHAGE
# ══════════════════════════════════════════════════════════════════

def tester_email(nom_test: str, raw_email: str, attendu: str):
    print(f"\n{'═'*55}")
    print(f"  TEST : {nom_test}")
    print(f"  Résultat attendu : {attendu}")
    print(f"{'═'*55}")

    # Parsing
    parsed = parse_email(raw_email)
    print(f"  Sujet      : {parsed.subject}")
    print(f"  Expéditeur : {parsed.sender_email}")
    print(f"  URLs       : {parsed.urls}")

    # Features
    features = extract_features(parsed)
    features = {k: (0 if v is None else v) for k, v in features.items()}

    # Features suspectes
    print(f"\n  Features suspectes détectées :")
    suspects = {
        "has_ip_in_url"           : features.get("has_ip_in_url"),
        "url_obfuscated"          : features.get("url_obfuscated"),
        "display_name_mismatch"   : features.get("display_name_mismatch"),
        "sender_domain_suspicious": features.get("sender_domain_suspicious"),
        "urgency_score"           : features.get("urgency_score"),
        "suspicious_url_keywords" : features.get("suspicious_url_keywords"),
    }
    for k, v in suspects.items():
        flag = "🔴" if v and v > 0 else "🟢"
        print(f"    {flag} {k:<30} : {v}")

    # Features réseau
    print(f"\n  Vérifications réseau :")
    print(f"    {'spf_valid':<25} : {features.get('spf_valid')}")
    print(f"    {'dkim_valid':<25} : {features.get('dkim_valid')}")
    print(f"    {'dmarc_valid':<25} : {features.get('dmarc_valid')}")
    print(f"    {'ssl_valid':<25} : {features.get('ssl_valid')}")
    print(f"    {'domain_age_days':<25} : {features.get('domain_age_days')}")
    print(f"    {'in_blacklist':<25} : {features.get('in_blacklist')}")

    # Prédiction
    text = parsed.subject + " " + parsed.body
    result = predictor.predict(features, text)

    print(f"\n  {'─'*45}")
    print(f"  RÉSULTAT      : {result['label']}")
    print(f"  Confiance     : {result['confidence']}%")
    print(f"  Risque        : {result['risk_level']}")
    print(f"  Bloqué à      : {result['blocked_at']}")
    print(f"  Raison        : {result['block_reason']}")
    print(f"  SVM utilisé   : {result['svm_used']}")
    print(f"  {'─'*45}")

    # Vérification
    obtenu = "PHISHING" if result["is_phishing"] else "LÉGITIME"
    if obtenu == attendu:
        print(f"  ✅ CORRECT — {obtenu} détecté comme prévu !")
    else:
        print(f"  ❌ ERREUR — attendu {attendu} mais obtenu {obtenu}")

    return obtenu == attendu


# ══════════════════════════════════════════════════════════════════
# LANCEMENT DES TESTS
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\n🚀 LANCEMENT DES TESTS DU PIPELINE PHISHGUARD AI")

    resultats = []

    resultats.append(tester_email(
        "Phishing classique avec IP",
        EMAIL_PHISHING_IP,
        "PHISHING"
    ))

    resultats.append(tester_email(
        "Phishing avec mots urgents",
        EMAIL_PHISHING_URGENT,
        "PHISHING"
    ))

    resultats.append(tester_email(
        "Phishing usurpation Google",
        EMAIL_PHISHING_GOOGLE,
        "PHISHING"
    ))

    resultats.append(tester_email(
        "Email légitime simple",
        EMAIL_LEGITIME_SIMPLE,
        "LÉGITIME"
    ))

    resultats.append(tester_email(
        "Email légitime professionnel",
        EMAIL_LEGITIME_PRO,
        "LÉGITIME"
    ))

    # Résumé final
    total  = len(resultats)
    reussi = sum(resultats)

    print(f"\n{'═'*55}")
    print(f"  RÉSUMÉ FINAL")
    print(f"{'═'*55}")
    print(f"  Tests réussis  : {reussi}/{total}")
    print(f"  Taux de succès : {reussi/total*100:.0f}%")
    if reussi == total:
        print(f"  🏆 TOUS LES TESTS SONT PASSÉS !")
    else:
        print(f"  ⚠️  {total-reussi} test(s) ont échoué")
    print(f"{'═'*55}")