import os

import gradio as gr
import requests

API_BASE = os.getenv("API_BASE_URL", "http://127.0.0.1:8000")
API_EMAIL  = f"{API_BASE}/api/v1/analyze/email"
API_URL    = f"{API_BASE}/api/v1/analyze/url"
API_TOKEN  = f"{API_BASE}/api/v1/auth/token"

# Credentials de l'UI — compte dédié à l'interface
UI_USERNAME = "analyst"
UI_PASSWORD = "analyst123"


def get_token() -> str:
    """Obtient un token JWT frais avant chaque analyse."""
    r = requests.post(
        API_TOKEN,
        data={"username": UI_USERNAME, "password": UI_PASSWORD},
        timeout=10
    )
    r.raise_for_status()
    return r.json()["access_token"]


def auth_headers() -> dict:
    """Retourne les headers avec token JWT pour les requêtes API."""
    token = get_token()
    return {"Authorization": f"Bearer {token}"}
# ══════════════════════════════════════════════════════════════════
# CSS PERSONNALISÉ
# ══════════════════════════════════════════════════════════════════

CSS = """
.phishing-verdict {
    background: linear-gradient(135deg, #ff4444, #cc0000);
    color: white;
    padding: 20px;
    border-radius: 12px;
    font-size: 1.4em;
    font-weight: bold;
    text-align: center;
    margin: 10px 0;
}
.legitime-verdict {
    background: linear-gradient(135deg, #00aa44, #007733);
    color: white;
    padding: 20px;
    border-radius: 12px;
    font-size: 1.4em;
    font-weight: bold;
    text-align: center;
    margin: 10px 0;
}
.suspect-box {
    background: #fff3cd;
    border-left: 5px solid #ff9800;
    padding: 12px 16px;
    border-radius: 8px;
    margin: 8px 0;
    font-size: 0.95em;
}
.safe-box {
    background: #d4edda;
    border-left: 5px solid #28a745;
    padding: 12px 16px;
    border-radius: 8px;
    margin: 8px 0;
    font-size: 0.95em;
}
.confidence-bar-high {
    background: #dc3545;
    height: 24px;
    border-radius: 12px;
    color: white;
    text-align: center;
    line-height: 24px;
    font-weight: bold;
}
.confidence-bar-low {
    background: #28a745;
    height: 24px;
    border-radius: 12px;
    color: white;
    text-align: center;
    line-height: 24px;
    font-weight: bold;
}
"""

# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════

def build_verdict_html(is_phishing: bool, confidence: float, risk_level: str, blocked_at: str) -> str:
    if is_phishing:
        css_class     = "phishing-verdict"
        icon          = "🚨"
        label         = "PHISHING DÉTECTÉ"
        score_label   = "Score de risque phishing"
        score_value   = confidence
        bar_class     = "confidence-bar-high"
    else:
        css_class     = "legitime-verdict"
        icon          = "✅"
        label         = "EMAIL LÉGITIME"
        score_label   = "Confiance légitimité"
        score_value   = round(100 - confidence, 2)  # ← inversion ici
        bar_class     = "confidence-bar-low"

    bar_width = max(int(score_value), 5)

    return f"""
<div class="{css_class}">
    {icon} {label}
</div>
<div style="margin: 12px 0;">
    <b>📊 {score_label} :</b> {score_value}%
    <div style="background:#eee; border-radius:12px; margin-top:6px; overflow:hidden;">
        <div class="{bar_class}" style="width:{bar_width}%">{score_value}%</div>
    </div>
</div>
<div style="margin: 8px 0;">
    <b>⚡ Niveau de risque :</b> {risk_level}
</div>
<div style="margin: 8px 0;">
    <b>🔍 Détecté par :</b> {blocked_at}
</div>
"""


def build_suspicious_html(suspicious_elements: list) -> str:
    if not suspicious_elements:
        return '<div class="safe-box">✅ Aucun élément suspect détecté.</div>'
    
    html = f"<b>⚠️ {len(suspicious_elements)} élément(s) suspect(s) :</b><br>"
    for elem in suspicious_elements:
        html += f'<div class="suspect-box">🔴 {elem}</div>'
    return html


def build_network_html(features: dict) -> str:
    checks = [
        ("SPF",         features.get("spf_valid",   0)),
        ("DKIM",        features.get("dkim_valid",  0)),
        ("DMARC",       features.get("dmarc_valid", 0)),
        ("SSL",         features.get("ssl_valid",   0)),
        ("Blacklist",   features.get("in_blacklist", 0)),
    ]

    html = "<b>🌐 Vérifications réseau :</b><br><div style='display:flex; flex-wrap:wrap; gap:8px; margin-top:8px;'>"
    for name, val in checks:
        if name == "Blacklist":
            color = "#dc3545" if val == 1 else "#28a745"
            icon  = "🔴" if val == 1 else "🟢"
        else:
            color = "#28a745" if val == 1 else "#dc3545"
            icon  = "✅" if val == 1 else "❌"
        html += f"<span style='background:{color}20; border:1px solid {color}; padding:4px 10px; border-radius:20px; font-size:0.9em;'>{icon} {name}</span>"
    
    age = features.get("domain_age_days", -1)
    age_text = f"{age} jours" if age != -1 else "inconnu"
    age_color = "#dc3545" if age != -1 and age < 30 else "#6c757d"
    html += f"<span style='background:{age_color}20; border:1px solid {age_color}; padding:4px 10px; border-radius:20px; font-size:0.9em;'>📅 Âge domaine : {age_text}</span>"
    html += "</div>"
    return html


def build_url_features_html(features: dict) -> str:
    items = [
        ("Nombre d'URLs",       features.get("url_count", 0),              False),
        ("Longueur URL moy.",   features.get("url_length_avg", 0),         False),
        ("IP dans URL",         features.get("has_ip_in_url", 0),          True),
        ("URL obfusquée",       features.get("url_obfuscated", 0),         True),
        ("URL sans HTTPS",      1 - features.get("url_has_https", 1),      True),
        ("TLD suspect",         features.get("url_tld_suspect", 0),        True),
        ("Mots-clés suspects",  features.get("suspicious_url_keywords", 0), True),
        ("Sous-domaines",       features.get("subdomain_count", 0),        False),
    ]

    html = "<b>🔗 Analyse des URLs :</b><br><table style='width:100%; margin-top:8px; border-collapse:collapse;'>"
    for label, val, is_risk in items:
        if is_risk and val:
            color = "#dc3545"
            icon  = "🔴"
        else:
            color = "#28a745"
            icon  = "🟢"
        html += f"<tr style='border-bottom:1px solid #eee;'><td style='padding:6px;'>{label}</td><td style='color:{color}; padding:6px;'>{icon} {val}</td></tr>"
    html += "</table>"
    return html


# ══════════════════════════════════════════════════════════════════
# LOGIQUE MÉTIER
# ══════════════════════════════════════════════════════════════════

def analyze_eml(file):
    """Analyse un fichier .eml uploadé."""
    if file is None:
        return "<p style='color:gray;'>⬆️ Veuillez uploader un fichier .eml</p>", "", "", ""

    try:
        with open(file.name, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        response = requests.post(API_EMAIL, json={"raw_email": content}, headers=auth_headers(), timeout=200)
        response.raise_for_status()
        data = response.json()

        verdict_html    = build_verdict_html(
            data["is_phishing"],
            data["confidence"],
            data.get("report", "").split("Niveau risque :")[1].split("\n")[0].strip() if "Niveau risque :" in data.get("report", "") else "—",
            data.get("report", "").split("Détecté par   :")[1].split("\n")[0].strip() if "Détecté par   :" in data.get("report", "") else "—",
        )
        suspicious_html = build_suspicious_html(data.get("suspicious_elements", []))
        network_html    = build_network_html(data.get("features", {}))
        url_html        = build_url_features_html(data.get("features", {}))

        return verdict_html, suspicious_html, network_html, url_html

    except requests.exceptions.ConnectionError:
        return "<div style='color:red;'>❌ Impossible de joindre l'API. Vérifiez que le serveur FastAPI est lancé sur le port 8000.</div>", "", "", ""
    except Exception as e:
        return f"<div style='color:red;'>❌ Erreur : {str(e)}</div>", "", "", ""


def analyze_url(url: str):
    """Analyse une URL."""
    if not url or not url.strip():
        return "<p style='color:gray;'>🔗 Veuillez entrer une URL</p>", "", ""

    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = requests.post(API_URL, json={"url": url}, headers=auth_headers(), timeout=200)
        response.raise_for_status()
        data = response.json()

        verdict_html    = build_verdict_html(
            data["is_phishing"],
            data["confidence"],
            "CRITIQUE" if data["confidence"] >= 80 else "ÉLEVÉ" if data["confidence"] >= 60 else "MODÉRÉ" if data["confidence"] >= 40 else "FAIBLE",
            "Analyse URL"
        )
        suspicious_html = build_suspicious_html(data.get("suspicious_elements", []))
        url_html        = build_url_features_html(data.get("features", {}))

        return verdict_html, suspicious_html, url_html

    except requests.exceptions.ConnectionError:
        return "<div style='color:red;'>❌ Impossible de joindre l'API. Vérifiez que le serveur FastAPI est lancé sur le port 8000.</div>", "", ""
    except Exception as e:
        return f"<div style='color:red;'>❌ Erreur : {str(e)}</div>", "", ""


# ══════════════════════════════════════════════════════════════════
# INTERFACE GRADIO
# ══════════════════════════════════════════════════════════════════

with gr.Blocks(title="PhishGuard AI", css=CSS, theme=gr.themes.Soft()) as app:

    # ── Header ──────────────────────────────────────────────────
    gr.HTML("""
    <div style="text-align:center; padding: 24px 0 8px 0;">
        <h1 style="font-size:2.2em; margin:0;">🛡️ PhishGuard AI</h1>
        <p style="color:#666; margin:8px 0 0 0; font-size:1.1em;">
            Système intelligent de détection et de prévention du phishing
        </p>
        <p style="color:#999; font-size:0.85em;">ENSI · Université de la Manouba · 2025/2026</p>
    </div>
    """)

    with gr.Tabs():

        # ══ ONGLET 1 : EMAIL ════════════════════════════════════
        with gr.Tab("📄 Analyser un Email (.eml)"):
            gr.Markdown("### Uploadez un fichier `.eml` pour analyser s'il s'agit d'une tentative de phishing.")

            with gr.Row():
                with gr.Column(scale=1):
                    file_input = gr.File(
                        label="📎 Fichier email (.eml)",
                        file_types=[".eml", ".txt"],
                    )
                    btn_email = gr.Button("🔍 Analyser l'email", variant="primary", size="lg")

                with gr.Column(scale=2):
                    email_verdict  = gr.HTML(label="Verdict")
                    email_suspects = gr.HTML(label="Éléments suspects")

            with gr.Row():
                with gr.Column():
                    email_network = gr.HTML(label="Vérifications réseau")
                with gr.Column():
                    email_urls = gr.HTML(label="Analyse URLs")

            btn_email.click(
                analyze_eml,
                inputs=[file_input],
                outputs=[email_verdict, email_suspects, email_network, email_urls]
            )

        # ══ ONGLET 2 : URL ══════════════════════════════════════
        with gr.Tab("🌐 Analyser une URL"):
            gr.Markdown("### Entrez une URL pour vérifier si elle est malveillante.")

            with gr.Row():
                with gr.Column(scale=2):
                    url_input = gr.Textbox(
                        label="🔗 URL à analyser",
                        placeholder="https://exemple.com/login",
                        lines=1
                    )
                    btn_url = gr.Button("🔍 Analyser l'URL", variant="primary", size="lg")

                with gr.Column(scale=2):
                    url_verdict  = gr.HTML(label="Verdict")
                    url_suspects = gr.HTML(label="Éléments suspects")

            url_features_out = gr.HTML(label="Détail des features URL")

            btn_url.click(
                analyze_url,
                inputs=[url_input],
                outputs=[url_verdict, url_suspects, url_features_out]
            )

        # ══ ONGLET 3 : AIDE ═════════════════════════════════════
        with gr.Tab("ℹ️ Guide d'utilisation"):
            gr.HTML("""
            <div style="max-width:700px; margin:0 auto; padding:16px;">
                <h2>Comment utiliser PhishGuard AI ?</h2>

                <h3>📄 Analyse d'email</h3>
                <ol>
                    <li>Ouvrez votre client mail (Outlook, Thunderbird, Gmail...)</li>
                    <li>Exportez l'email suspect au format <b>.eml</b></li>
                    <li>Uploadez le fichier dans l'onglet "Analyser un Email"</li>
                    <li>Cliquez sur <b>Analyser</b></li>
                </ol>

                <h3>🌐 Analyse d'URL</h3>
                <ol>
                    <li>Copiez l'URL suspecte</li>
                    <li>Collez-la dans l'onglet "Analyser une URL"</li>
                    <li>Cliquez sur <b>Analyser</b></li>
                </ol>

                <h3>📊 Comprendre les résultats</h3>
                <table style="width:100%; border-collapse:collapse;">
                    <tr style="background:#f8f9fa;">
                        <th style="padding:8px; border:1px solid #dee2e6;">Indicateur</th>
                        <th style="padding:8px; border:1px solid #dee2e6;">Signification</th>
                    </tr>
                    <tr>
                        <td style="padding:8px; border:1px solid #dee2e6;">🚨 PHISHING</td>
                        <td style="padding:8px; border:1px solid #dee2e6;">Email ou URL détecté comme malveillant</td>
                    </tr>
                    <tr>
                        <td style="padding:8px; border:1px solid #dee2e6;">✅ LÉGITIME</td>
                        <td style="padding:8px; border:1px solid #dee2e6;">Aucune menace détectée</td>
                    </tr>
                    <tr>
                        <td style="padding:8px; border:1px solid #dee2e6;">Confiance ≥ 80%</td>
                        <td style="padding:8px; border:1px solid #dee2e6;">Risque CRITIQUE — ne pas interagir</td>
                    </tr>
                    <tr>
                        <td style="padding:8px; border:1px solid #dee2e6;">SPF / DKIM / DMARC</td>
                        <td style="padding:8px; border:1px solid #dee2e6;">Vérifications d'authenticité de l'expéditeur</td>
                    </tr>
                </table>

                <h3>⚠️ Limitations</h3>
                <ul>
                    <li>Les vérifications réseau (SPF/DKIM) nécessitent une connexion internet active</li>
                    <li>Les URLs raccourcies sont détectées mais non résolues</li>
                    <li>L'intégration blacklist Google Safe Browsing est en cours</li>
                </ul>
            </div>
            """)

    # ── Footer ───────────────────────────────────────────────────
    gr.HTML("""
    <div style="text-align:center; padding:16px; color:#999; font-size:0.85em; border-top:1px solid #eee; margin-top:24px;">
        PhishGuard AI v1.0 · MANSOUR Lina &amp; JAWEDI Maryem · Encadré par BOUSAADA Rihab
    </div>
    """)


if __name__ == "__main__":
    app.launch(
        server_name="0.0.0.0",   # accessible depuis l'extérieur du conteneur
        server_port=7860,
        show_error=True
    )
    