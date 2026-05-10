"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         ÉVALUATION PIPELINE COMPLET — PhishGuard AI                        ║
║         30 cas de test : emails + URLs                                      ║
║         Lancer : python tests/evaluation/test_pipeline_complet.py           ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import sys
import os
import requests
import time
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

API_BASE   = "http://127.0.0.1:8000"
API_EMAIL  = f"{API_BASE}/api/v1/analyze/email"
API_URL    = f"{API_BASE}/api/v1/analyze/url"
API_HEALTH = f"{API_BASE}/health"
TIMEOUT    = 60


# ══════════════════════════════════════════════════════════════════════════════
# JEUX DE TEST — EMAILS PHISHING  (15 cas)
# ══════════════════════════════════════════════════════════════════════════════

EMAILS_PHISHING = [

    # ── 1. Phishing PayPal classique ──────────────────────────────────────────
    ("Phishing PayPal urgent",
     """From: "PayPal Security" <security@paypal-alert-update.xyz>
Subject: URGENT!!! Your PayPal account has been SUSPENDED
Content-Type: text/plain

Dear Customer,
WARNING: Unusual activity detected on your account!
Your account will be permanently suspended in 24 hours.
Click here immediately: http://paypal-secure-login.xyz/verify?account=update
This is your FINAL WARNING!!!
"""),

    # ── 2. Phishing Google avec IP dans l'URL ─────────────────────────────────
    ("Phishing Google IP brute",
     """From: "Google Team" <noreply@google-secure-verify.tk>
Subject: Action required: Verify your Google account
Content-Type: text/plain

Your Google account will be suspended in 24 hours.
Please verify immediately: http://192.168.1.1/google/login?confirm=true
"""),

    # ── 3. Phishing Apple ID ──────────────────────────────────────────────────
    ("Phishing Apple ID",
     """From: "Apple Support" <no-reply@apple-id-verify.ml>
Subject: Your Apple ID has been locked
Content-Type: text/plain

Your Apple ID has been locked due to suspicious activity.
To unlock your account, please verify your identity:
http://appleid-secure.ml/unlock?session=expired&confirm=true
Enter your password and confirm your details urgently.
Apple Security Team
"""),

    # ── 4. Phishing Netflix ───────────────────────────────────────────────────
    ("Phishing Netflix renouvellement",
     """From: "Netflix Billing" <billing@netflix-account-update.cf>
Subject: Your Netflix membership will be cancelled
Content-Type: text/plain

We were unable to process your payment.
Update your billing information immediately to avoid service interruption:
http://netflix-billing-update.cf/secure/payment?account=renew
"""),

    # ── 5. Phishing bancaire ──────────────────────────────────────────────────
    ("Phishing banque CIB",
     """From: "CIB Bank Security" <alert@cib-bank-secure.xyz>
Subject: Alerte de sécurité — Connexion suspecte détectée
Content-Type: text/plain

Nous avons détecté une connexion inhabituelle sur votre compte bancaire.
Veuillez confirmer votre identité immédiatement :
http://cib-bank-secure.xyz/login/verify?update=true
Ne pas répondre à cet email pourrait entraîner la suspension de votre compte.
"""),

    # ── 6. Phishing Microsoft Office 365 ─────────────────────────────────────
    ("Phishing Microsoft 365",
     """From: "Microsoft Account Team" <account@microsoftonline-secure.pw>
Subject: Your Microsoft account password expires today
Content-Type: text/plain

Your Microsoft Office 365 password expires today.
Click the link below to update your password now:
http://microsoftonline-secure.pw/update?account=office365&confirm=true
Failure to update will result in account suspension.
"""),

    # ── 7. Phishing DHL livraison ──────────────────────────────────────────────
    ("Phishing DHL livraison",
     """From: "DHL Express" <tracking@dhl-delivery-confirm.tk>
Subject: Your DHL package is on hold — Action required
Content-Type: text/plain

Your package cannot be delivered due to incorrect address.
Please confirm your delivery address and pay the customs fee:
http://dhl-delivery-confirm.tk/tracking?parcel=DHL928374&pay=true
You have 48 hours before your package is returned.
"""),

    # ── 8. Phishing Amazon commande ───────────────────────────────────────────
    ("Phishing Amazon commande suspecte",
     """From: "Amazon Customer Service" <orders@amazon-account-verify.ru>
Subject: Unusual sign-in activity on your Amazon account
Content-Type: text/plain

We noticed unusual sign-in activity on your Amazon account.
To secure your account, please verify your identity immediately:
http://amazon-account-verify.ru/secure/signin?confirm=true
If you do not verify within 12 hours, your account will be locked.
Amazon Security Team
"""),

    # ── 9. Phishing avec URL obfusquée ────────────────────────────────────────
    ("Phishing URL obfusquée",
     """From: "Secure Login" <login@secure-banking-verify.xyz>
Subject: URGENT: Verify your banking account now
Content-Type: text/plain

Your account has been compromised. Verify immediately:
http://secure-banking.com%40evil-phish.xyz/login?verify=true
This is your last chance to secure your account!!!!
"""),

    # ── 10. Phishing loterie gagnant ──────────────────────────────────────────
    ("Phishing loterie gagnant",
     """From: "International Lottery" <winner@prize-claim-now.tk>
Subject: CONGRATULATIONS!!! You have won $500,000!!!
Content-Type: text/plain

CONGRATULATIONS WINNER!!!
You have been selected as our lucky winner.
Claim your prize immediately by clicking:
http://prize-claim-now.tk/winner?claim=500000&verify=true
Act NOW! This offer expires in 24 hours!!!
"""),

    # ── 11. Phishing impôts / gouvernement ────────────────────────────────────
    ("Phishing remboursement impôts",
     """From: "Direction Générale des Impôts" <refund@impots-dgi-tn.xyz>
Subject: Remboursement fiscal en attente — Action requise
Content-Type: text/plain

Madame, Monsieur,
Un remboursement fiscal de 847 DT vous est dû.
Pour recevoir votre remboursement, confirmez vos coordonnées bancaires :
http://impots-dgi-remboursement.xyz/refund?montant=847&confirm=true
Ce remboursement expirera dans 48h.
"""),

    # ── 12. Phishing LinkedIn mot de passe ────────────────────────────────────
    ("Phishing LinkedIn mot de passe",
     """From: "LinkedIn Security" <security@linkedin-account-secure.ml>
Subject: Your LinkedIn password needs to be reset
Content-Type: text/plain

Someone tried to access your LinkedIn account from an unknown device.
Reset your password immediately to secure your account:
http://linkedin-account-secure.ml/reset?token=abc123&confirm=true
"""),

    # ── 13. Phishing facture urgent ───────────────────────────────────────────
    ("Phishing fausse facture",
     """From: "Accounting Department" <invoice@facture-urgent-pay.cc>
Subject: URGENT: Invoice #INV-2026-0847 overdue — Pay now
Content-Type: text/plain

Your invoice is overdue. Failure to pay will result in legal action.
Pay immediately via this secure link:
http://facture-urgent-pay.cc/invoice?id=INV-2026-0847&amount=1200
"""),

    # ── 14. Phishing WhatsApp vérification ────────────────────────────────────
    ("Phishing WhatsApp code",
     """From: "WhatsApp Team" <verify@whatsapp-secure-confirm.gq>
Subject: Your WhatsApp verification code is about to expire
Content-Type: text/plain

Your WhatsApp account needs to be verified.
Enter your verification code at:
http://whatsapp-secure-confirm.gq/verify?code=expiring&account=update
"""),

    # ── 15. Phishing COVID aide gouvernement ──────────────────────────────────
    ("Phishing aide COVID",
     """From: "Ministère de la Santé" <aide@covid-aide-tn-gov.top>
Subject: Votre aide COVID-19 est disponible — Réclamez maintenant
Content-Type: text/plain

Suite à la pandémie, vous êtes éligible à une aide de 500 DT.
Réclamez votre aide immédiatement en confirmant vos informations :
http://covid-aide-tn-gov.top/claim?montant=500&cin=confirm
Cette aide expire dans 24 heures. Ne manquez pas cette opportunité!
"""),
]


# ══════════════════════════════════════════════════════════════════════════════
# JEUX DE TEST — EMAILS LÉGITIMES  (15 cas)
# ══════════════════════════════════════════════════════════════════════════════

EMAILS_LEGITIMES = [

    # ── 1. Réunion collègue simple ────────────────────────────────────────────
    ("Légitime réunion collègue",
     """From: "Alice Martin" <alice.martin@gmail.com>
Subject: Reunion de demain
Content-Type: text/plain

Bonjour,
Je voulais confirmer notre reunion de demain a 10h dans la salle B.
N'oublie pas d'apporter le rapport de la semaine derniere.
A demain,
Alice
"""),

    # ── 2. RH bulletin de salaire ─────────────────────────────────────────────
    ("Légitime RH bulletin salaire",
     """From: "Service RH" <rh@entreprise.fr>
Subject: Votre bulletin de salaire - Mars 2026
Content-Type: text/plain

Bonjour,
Veuillez trouver ci-joint votre bulletin de salaire pour mars 2026.
Pour toute question, contactez le service RH.
Cordialement,
Le Service des Ressources Humaines
"""),

    # ── 3. Maintenance informatique planifiée ────────────────────────────────
    ("Légitime maintenance informatique",
     """From: "IT Support" <it@company-internal.com>
Subject: Scheduled maintenance this weekend
Content-Type: text/plain

Dear team,
We will be performing scheduled maintenance on our servers this Saturday
from 22:00 to 02:00. Services may be temporarily unavailable.
No action is required from your side.
Best regards,
IT Support Team
"""),

    # ── 4. Invitation conférence ──────────────────────────────────────────────
    ("Légitime invitation conférence",
     """From: "Comité ENSI" <comite@ensi.rnu.tn>
Subject: Invitation - Journée des projets de fin d'études 2026
Content-Type: text/plain

Chère étudiante,
Nous avons le plaisir de vous inviter à la journée de présentation
des projets de fin d'études qui aura lieu le 15 juin 2026 à 9h.
Merci de confirmer votre participation.
Cordialement,
Le Comité Pédagogique
"""),

    # ── 5. Commande e-commerce confirmée ─────────────────────────────────────
    ("Légitime confirmation commande",
     """From: "Jumia Tunisie" <orders@jumia.com.tn>
Subject: Votre commande #JUM-20260418 a été confirmée
Content-Type: text/plain

Bonjour,
Votre commande #JUM-20260418 a bien été enregistrée.
Montant total : 149 DT
Livraison prévue entre le 20 et 22 avril 2026.
Merci pour votre confiance.
L'équipe Jumia
"""),

    # ── 6. Email personnel entre amis ────────────────────────────────────────
    ("Légitime email personnel",
     """From: "Mohamed Ben Ali" <med.benali@outlook.com>
Subject: Weekend prochain
Content-Type: text/plain

Slt,
Tu es libre ce weekend ? On pense organiser un match de foot samedi après-midi.
On serait une dizaine. Réponds-moi si tu peux venir.
À plus,
Med
"""),

    # ── 7. Newsletter abonnement légitime ─────────────────────────────────────
    ("Légitime newsletter abonnement",
     """From: "Medium Daily Digest" <noreply@medium.com>
Subject: Your daily reading list for today
Content-Type: text/plain

Here are today's top stories based on your interests:

- How to build a production-ready REST API with FastAPI
- Understanding transformer models from scratch
- 10 tips to write cleaner Python code

Visit medium.com to read these stories.
You are receiving this because you subscribed to Medium Daily Digest.
"""),

    # ── 8. Rappel paiement facture téléphone ─────────────────────────────────
    ("Légitime facture téléphone",
     """From: "Ooredoo Tunisie" <facture@ooredoo.tn>
Subject: Votre facture du mois d'avril est disponible
Content-Type: text/plain

Bonjour,
Votre facture mensuelle d'un montant de 45,000 DT est disponible.
Vous pouvez la consulter et la régler depuis votre espace client MyOoredoo.
Date d'échéance : 30 avril 2026.
Cordialement,
Ooredoo Service Client
"""),

    # ── 9. Email académique université ───────────────────────────────────────
    ("Légitime email académique",
     """From: "Secretariat ENSI" <secretariat@ensi.rnu.tn>
Subject: Calendrier des examens - Session principale 2026
Content-Type: text/plain

Chère étudiante,
Nous vous informons que le calendrier des examens de la session principale
a été publié sur le portail étudiant.
Les examens débuteront le 2 juin 2026.
Bonne préparation.
Le Secrétariat
"""),

    # ── 10. Réponse à un email professionnel ─────────────────────────────────
    ("Légitime réponse professionnelle",
     """From: "Dr. Rihab Bousaada" <r.bousaada@ensi.rnu.tn>
Subject: Re: Rapport PCD - retour corrections
Content-Type: text/plain

Bonjour,
J'ai bien reçu votre rapport. Les corrections demandées sont pertinentes.
Merci de les intégrer pour la version finale avant le 25 avril.
Bon courage pour la soutenance.
Dr. Bousaada
"""),

    # ── 11. Invitation LinkedIn connexion ─────────────────────────────────────
    ("Légitime invitation LinkedIn",
     """From: "LinkedIn" <invitations@linkedin.com>
Subject: Ahmed Trabelsi wants to connect with you on LinkedIn
Content-Type: text/plain

Ahmed Trabelsi wants to add you to their professional network.

Ahmed Trabelsi
Software Engineer at Vermeg

View profile and respond on LinkedIn.

You are receiving this because you are a LinkedIn member.
"""),

    # ── 12. Notification GitHub ───────────────────────────────────────────────
    ("Légitime notification GitHub",
     """From: "GitHub" <noreply@github.com>
Subject: [PhishGuard-AI] Pull request #12 opened by teammate
Content-Type: text/plain

A new pull request was opened on your repository.

Repository: username/phishguard-ai
PR #12: Add URL reputation checker integration
Opened by: team-member

You can review this pull request on GitHub.
"""),

    # ── 13. Confirmation rendez-vous médical ─────────────────────────────────
    ("Légitime rdv médical",
     """From: "Cabinet Dr. Sassi" <rdv@cabinet-sassi.tn>
Subject: Rappel de votre rendez-vous - Demain 14h30
Content-Type: text/plain

Bonjour,
Ce message est un rappel de votre rendez-vous prévu demain
vendredi 19 avril 2026 à 14h30.
En cas d'empêchement, merci de nous prévenir au 71 000 000.
Cabinet médical Dr. Sassi
"""),

    # ── 14. Email parent à enfant ─────────────────────────────────────────────
    ("Légitime email familial",
     """From: "Maman" <fatma.parent@yahoo.fr>
Subject: Nouvelles de la famille
Content-Type: text/plain

Ma chérie,
Ton père et moi pensons à toi. Comment avance ton projet de fin d'études ?
Ton frère a eu son permis de conduire la semaine dernière.
On t'attend pour les vacances de l'Aïd.
Grosses bises,
Maman
"""),

    # ── 15. Offre d'emploi légitime ───────────────────────────────────────────
    ("Légitime offre d'emploi",
     """From: "RH Telnet" <recrutement@telnet.tn>
Subject: Suite à votre candidature - Ingénieur Développement
Content-Type: text/plain

Bonjour Mme Mansour,
Nous avons bien reçu votre candidature pour le poste d'Ingénieur Développement.
Après examen de votre dossier, nous souhaitons vous rencontrer pour un entretien.
Merci de nous confirmer vos disponibilités pour la semaine du 22 avril.
Cordialement,
Service Recrutement Telnet
"""),
]


# ══════════════════════════════════════════════════════════════════════════════
# JEUX DE TEST — URLs  (20 cas : 10 phishing + 10 légitimes)
# ══════════════════════════════════════════════════════════════════════════════

URLS_PHISHING = [
    ("URL IP brute",              "http://192.168.1.100/login?verify=account"),
    ("URL TLD .tk",               "http://paypal-secure-login.tk/verify?update=true"),
    ("URL TLD .xyz",              "http://google-account-verify.xyz/secure/login"),
    ("URL TLD .ml",               "http://apple-id-verify.ml/unlock?session=expired"),
    ("URL avec mots suspects",    "http://evil.com/secure/login/verify/account/confirm/password"),
    ("URL obfusquée @",           "http://paypal.com%40phishing-site.com/steal"),
    ("URL raccourcie",            "http://bit.ly/3xPhish99"),
    ("URL extension .exe",        "http://malware-site.ru/downloads/installer.exe"),
    ("URL redirect suspect",      "http://evil.com/redirect?url=http://phishing.com&goto=login"),
    ("URL long + TLD suspect",    "http://secure-verify-account-update-login-paypal.top/confirm?id=12345&token=abc"),
]

URLS_LEGITIMES = [
    ("URL Google HTTPS",          "https://www.google.com/search?q=phishing+detection"),
    ("URL GitHub repo",           "https://github.com/user/phishguard-ai"),
    ("URL Wikipedia",             "https://fr.wikipedia.org/wiki/Hame%C3%A7onnage"),
    ("URL YouTube",               "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
    ("URL LinkedIn profil",       "https://www.linkedin.com/in/username"),
    ("URL Stack Overflow",        "https://stackoverflow.com/questions/12345/how-to-detect-phishing"),
    ("URL Medium article",        "https://medium.com/@author/building-phishing-detector-python"),
    ("URL ENSI",                  "https://www.ensi.rnu.tn/fr/formations"),
    ("URL PyPI package",          "https://pypi.org/project/scikit-learn/"),
    ("URL AWS documentation",     "https://docs.aws.amazon.com/ec2/latest/userguide/"),
]


# ══════════════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def check_api():
    try:
        r = requests.get(API_HEALTH, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def run_email_test(nom: str, raw_email: str, attendu: str) -> dict:
    start = time.time()
    try:
        r = requests.post(API_EMAIL, json={"raw_email": raw_email}, timeout=TIMEOUT)
        elapsed = round(time.time() - start, 2)
        if r.status_code != 200:
            return {"ok": False, "nom": nom, "attendu": attendu,
                    "obtenu": f"HTTP {r.status_code}", "conf": 0, "elapsed": elapsed}
        data    = r.json()
        label   = "PHISHING" if data["is_phishing"] == 1 else "LÉGITIME"
        conf    = data.get("confidence", 0)
        correct = (label == attendu)
        return {"ok": correct, "nom": nom, "attendu": attendu,
                "obtenu": label, "conf": conf, "elapsed": elapsed}
    except Exception as e:
        return {"ok": False, "nom": nom, "attendu": attendu,
                "obtenu": f"ERREUR: {e}", "conf": 0,
                "elapsed": round(time.time() - start, 2)}


def run_url_test(nom: str, url: str, attendu: str) -> dict:
    start = time.time()
    try:
        r = requests.post(API_URL, json={"url": url}, timeout=TIMEOUT)
        elapsed = round(time.time() - start, 2)
        if r.status_code != 200:
            return {"ok": False, "nom": nom, "attendu": attendu,
                    "obtenu": f"HTTP {r.status_code}", "conf": 0, "elapsed": elapsed}
        data    = r.json()
        label   = "PHISHING" if data["is_phishing"] == 1 else "LÉGITIME"
        conf    = data.get("confidence", 0)
        correct = (label == attendu)
        return {"ok": correct, "nom": nom, "attendu": attendu,
                "obtenu": label, "conf": conf, "elapsed": elapsed,
                "url": url}
    except Exception as e:
        return {"ok": False, "nom": nom, "attendu": attendu,
                "obtenu": f"ERREUR: {e}", "conf": 0,
                "elapsed": round(time.time() - start, 2), "url": url}


def print_result(i: int, total: int, r: dict):
    icon = "✅" if r["ok"] else "❌"
    print(f"[{i:02d}/{total}] {r['nom']}")
    print(f"         Attendu : {r['attendu']}")
    print(f"         Obtenu  : {r['obtenu']} ({r['conf']}%) — {r['elapsed']}s")
    print(f"         {icon} {'CORRECT' if r['ok'] else 'ERREUR'}")


def compute_metrics(results: list, pos_label: str = "PHISHING") -> dict:
    tp = sum(1 for r in results if r["attendu"] == pos_label and r["obtenu"] == pos_label)
    tn = sum(1 for r in results if r["attendu"] != pos_label and r["obtenu"] != pos_label)
    fp = sum(1 for r in results if r["attendu"] != pos_label and r["obtenu"] == pos_label)
    fn = sum(1 for r in results if r["attendu"] == pos_label and r["obtenu"] != pos_label)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    accuracy  = (tp + tn) / len(results) if results else 0
    fpr       = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision * 100, 1),
        "recall"   : round(recall    * 100, 1),
        "f1"       : round(f1        * 100, 1),
        "accuracy" : round(accuracy  * 100, 1),
        "fpr"      : round(fpr       * 100, 1),
    }


def print_matrix(m: dict, label_pos: str = "PHISH", label_neg: str = "LEGIT"):
    print(f"  Matrice de confusion :")
    print(f"  ┌─────────────┬──────────────┬──────────────┐")
    print(f"  │             │ Prédit {label_pos} │ Prédit {label_neg} │")
    print(f"  ├─────────────┼──────────────┼──────────────┤")
    print(f"  │ Réel {label_pos}  │ TP = {m['tp']:<8}│ FN = {m['fn']:<8}│")
    print(f"  │ Réel {label_neg}  │ FP = {m['fp']:<8}│ TN = {m['tn']:<8}│")
    print(f"  └─────────────┴──────────────┴──────────────┘")


def print_section_header(title: str):
    print(f"\n{'═'*65}")
    print(f"  {title}")
    print(f"{'═'*65}")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print(f"\n{'═'*65}")
    print(f"  ÉVALUATION PIPELINE COMPLET — PhishGuard AI")
    print(f"  {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print(f"  30 emails + 20 URLs = 50 cas de test")
    print(f"{'═'*65}")

    if not check_api():
        print("❌ API FastAPI inaccessible sur http://127.0.0.1:8000")
        print("   Lance d'abord : uvicorn src.api.main:app --reload --port 8000")
        sys.exit(1)
    print("✅ API disponible\n")

    all_email_results = []
    all_url_results   = []

    # ── Section 1 : Emails phishing ──────────────────────────────────────────
    print_section_header("SECTION 1/4 — Emails PHISHING (15 cas)")
    ep_results = []
    for i, (nom, raw) in enumerate(EMAILS_PHISHING, 1):
        r = run_email_test(nom, raw, "PHISHING")
        ep_results.append(r)
        all_email_results.append(r)
        print_result(i, 15, r)

    # ── Section 2 : Emails légitimes ─────────────────────────────────────────
    print_section_header("SECTION 2/4 — Emails LÉGITIMES (15 cas)")
    el_results = []
    for i, (nom, raw) in enumerate(EMAILS_LEGITIMES, 1):
        r = run_email_test(nom, raw, "LÉGITIME")
        el_results.append(r)
        all_email_results.append(r)
        print_result(i, 15, r)

    # ── Section 3 : URLs phishing ─────────────────────────────────────────────
    print_section_header("SECTION 3/4 — URLs PHISHING (10 cas)")
    up_results = []
    for i, (nom, url) in enumerate(URLS_PHISHING, 1):
        r = run_url_test(nom, url, "PHISHING")
        up_results.append(r)
        all_url_results.append(r)
        print_result(i, 10, r)
        print(f"         URL     : {r.get('url', '')[:70]}")

    # ── Section 4 : URLs légitimes ────────────────────────────────────────────
    print_section_header("SECTION 4/4 — URLs LÉGITIMES (10 cas)")
    ul_results = []
    for i, (nom, url) in enumerate(URLS_LEGITIMES, 1):
        r = run_url_test(nom, url, "LÉGITIME")
        ul_results.append(r)
        all_url_results.append(r)
        print_result(i, 10, r)
        print(f"         URL     : {r.get('url', '')[:70]}")

    # ── Métriques emails ──────────────────────────────────────────────────────
    print_section_header("RÉSULTATS — EMAILS (30 cas)")
    em = compute_metrics(all_email_results)
    times_email = [r["elapsed"] for r in all_email_results if isinstance(r["elapsed"], (int, float))]
    print(f"  Emails testés      : 30 (15 phishing / 15 légitimes)")
    print(f"  Corrects           : {em['tp']+em['tn']}/30")
    print(f"  Accuracy           : {em['accuracy']}%")
    print(f"  Précision          : {em['precision']}%")
    print(f"  Recall (détection) : {em['recall']}%")
    print(f"  F1-Score           : {em['f1']}%")
    print(f"  Taux faux positifs : {em['fpr']}%")
    print()
    print_matrix(em)
    print()
    print(f"  Temps moyen/email  : {round(sum(times_email)/len(times_email), 2)}s")
    print()
    ok_ph = sum(1 for r in ep_results if r["ok"])
    ok_le = sum(1 for r in el_results if r["ok"])
    print(f"  Critères PCD :")
    print(f"  BD-02 Faux positifs < 5%  : {'✅' if em['fpr'] < 5 else '❌'} ({em['fpr']}%)")
    print(f"  BD-03 Détection ≥ 95%     : {'✅' if em['recall'] >= 95 else '❌'} ({em['recall']}%)")
    print(f"  RNF-01 Temps < 30s/email  : {'✅' if max(times_email) < 30 else '❌'} (max {max(times_email)}s)")

    # ── Métriques URLs ────────────────────────────────────────────────────────
    print_section_header("RÉSULTATS — URLS (20 cas)")
    um = compute_metrics(all_url_results)
    times_url = [r["elapsed"] for r in all_url_results if isinstance(r["elapsed"], (int, float))]
    print(f"  URLs testées       : 20 (10 phishing / 10 légitimes)")
    print(f"  Corrects           : {um['tp']+um['tn']}/20")
    print(f"  Accuracy           : {um['accuracy']}%")
    print(f"  Précision          : {um['precision']}%")
    print(f"  Recall             : {um['recall']}%")
    print(f"  F1-Score           : {um['f1']}%")
    print(f"  Taux faux positifs : {um['fpr']}%")
    print()
    print_matrix(um)

    # ── Résumé global ─────────────────────────────────────────────────────────
    all_results  = all_email_results + all_url_results
    total_ok     = sum(1 for r in all_results if r["ok"])
    print_section_header("RÉSUMÉ GLOBAL (50 cas)")
    print(f"  Total correct      : {total_ok}/50")
    print(f"  Accuracy globale   : {round(total_ok/50*100, 1)}%")

    # Cas échoués
    failed = [r for r in all_results if not r["ok"]]
    if failed:
        print(f"\n  ❌ Cas en échec ({len(failed)}) :")
        for r in failed:
            print(f"     - {r['nom']} : attendu {r['attendu']}, obtenu {r['obtenu']} ({r['conf']}%)")
    else:
        print("\n  🏆 TOUS LES CAS SONT CORRECTS !")

    print(f"{'═'*65}\n")