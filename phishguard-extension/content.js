// ============================================================
// PhishGuard AI — content.js
// ============================================================

const BADGE_ID = "phishguard-badge";
const analyzedEmails = new Set();

const COLORS = {
  phishing: { bg: "#ff4444", border: "#cc0000", text: "#fff" },
  legitime:  { bg: "#00aa44", border: "#007733", text: "#fff" },
  loading:   { bg: "#f5a623", border: "#d4891a", text: "#fff" },
  error:     { bg: "#888",    border: "#555",    text: "#fff" },
};

// ============================================================
// BADGE
// ============================================================

function createBadge(state, message, confidence = null, suspects = []) {
  const old = document.getElementById(BADGE_ID);
  if (old) old.remove();

  const color = COLORS[state];
  const badge = document.createElement("div");
  badge.id = BADGE_ID;
  badge.style.cssText = `
    position: fixed; top: 80px; right: 20px; z-index: 9999;
    background: ${color.bg}; border: 2px solid ${color.border};
    border-radius: 12px; padding: 12px 16px;
    min-width: 260px; max-width: 320px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    font-size: 14px; color: ${color.text};
    transition: all 0.3s ease; cursor: pointer;
  `;

  const icon  = state === "phishing" ? "🚨" :
                state === "legitime" ? "✅" :
                state === "loading"  ? "🔍" : "⚠️";

  const title = state === "phishing" ? "PHISHING DÉTECTÉ" :
                state === "legitime" ? "EMAIL LÉGITIME"   :
                state === "loading"  ? "Analyse en cours..." : "Erreur API";

  badge.innerHTML = `
    <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;">
      <span style="font-size:20px">${icon}</span>
      <strong style="font-size:15px; letter-spacing:0.5px">${title}</strong>
      <span id="phishguard-close" style="margin-left:auto; cursor:pointer; opacity:0.8; font-size:16px">✕</span>
    </div>
    ${confidence !== null ? `
      <div style="margin-bottom:6px;">
        <div style="font-size:12px; opacity:0.9; margin-bottom:3px;">
          ${state === "phishing" ? "Score de risque" : "Confiance légitimité"} :
          <strong>${state === "phishing" ? confidence : Math.round(100 - confidence)}%</strong>
        </div>
        <div style="background:rgba(255,255,255,0.3); border-radius:6px; height:6px; overflow:hidden;">
          <div style="
            background:rgba(255,255,255,0.9); height:100%;
            width:${state === "phishing" ? confidence : Math.round(100 - confidence)}%;
            border-radius:6px;
          "></div>
        </div>
      </div>
    ` : ""}
    ${suspects.length > 0 ? `
      <div style="margin-top:8px; font-size:12px; border-top:1px solid rgba(255,255,255,0.3); padding-top:8px;">
        <div style="opacity:0.9; margin-bottom:4px;">⚠️ ${suspects.length} élément(s) suspect(s) :</div>
        ${suspects.slice(0, 3).map(s => `
          <div style="opacity:0.85; margin:2px 0;">• ${s}</div>
        `).join("")}
        ${suspects.length > 3 ? `<div style="opacity:0.7;">+ ${suspects.length - 3} autres...</div>` : ""}
      </div>
    ` : ""}
    <div style="margin-top:8px; font-size:11px; opacity:0.7; text-align:right;">
      PhishGuard AI
    </div>
  `;

  document.body.appendChild(badge);

  document.getElementById("phishguard-close")?.addEventListener("click", (e) => {
    e.stopPropagation();
    badge.remove();
  });

  if (state === "legitime") setTimeout(() => badge.remove(), 15000);
}

// ============================================================
// EXTRACTION DU MESSAGE ID DEPUIS L'URL
// ============================================================

function extractMessageId() {
  const hash = window.location.hash;
  const match = hash.match(/[#/]([A-Za-z0-9]{10,})(?:[#/?]|$)/);
  if (match) return match[1];

  const params = new URLSearchParams(window.location.search);
  const th = params.get("th");
  if (th) return th;

  return null;
}

// ============================================================
// EXTRACTION DU SUJET ET SENDER DEPUIS LE DOM
// ============================================================

function extractSubject() {
  return document.querySelector(".hP")?.innerText ||
         document.querySelector("h2.hP")?.innerText || "";
}

function extractSender() {
  return document.querySelector(".gD")?.getAttribute("email") ||
         document.querySelector(".go")?.innerText || "";
}

// ============================================================
// ENVOI À BACKGROUND.JS
// ============================================================

async function analyzeEmail(messageId, subject, sender) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(
      { type: "ANALYZE_EMAIL", messageId, subject, sender },
      (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (response.success) {
          resolve(response.data);
        } else {
          reject(new Error(response.error));
        }
      }
    );
  });
}

// ============================================================
// DÉTECTION DE L'OUVERTURE D'UN EMAIL
// ============================================================

async function onEmailOpened() {
  await new Promise(r => setTimeout(r, 800));

  const messageId = extractMessageId();
  console.log("[PhishGuard] URL actuelle :", window.location.href);
  console.log("[PhishGuard] MessageId extrait :", messageId);

  if (!messageId) {
    console.log("[PhishGuard] ❌ Pas de messageId — email pas encore ouvert ?");
    return;
  }

  if (analyzedEmails.has(messageId)) {
    console.log("[PhishGuard] ⏭️ Déjà analysé :", messageId);
    return;
  }
  analyzedEmails.add(messageId);

  const subject = extractSubject();
  const sender  = extractSender();
  console.log("[PhishGuard] Sujet :", subject, "| Sender :", sender);

  // On a besoin d'au moins le sender OU le sujet
  if (!subject && !sender) {
    console.log("[PhishGuard] ❌ Ni sujet ni sender — DOM pas encore chargé ?");
    analyzedEmails.delete(messageId); // permet de réessayer
    return;
  }

  createBadge("loading", "Analyse en cours...");

  try {
    const result = await analyzeEmail(messageId, subject, sender);
    console.log("[PhishGuard] ✅ Résultat reçu :", result);

    if (result.is_phishing) {
      createBadge(
        "phishing",
        "PHISHING DÉTECTÉ",
        result.confidence,
        result.suspicious_elements || []
      );
    } else {
      createBadge(
        "legitime",
        "EMAIL LÉGITIME",
        result.confidence,
        []
      );
    }
  } catch (err) {
    console.log("[PhishGuard] ❌ Erreur analyse :", err.message);
    createBadge("error", `Erreur : ${err.message}`);
  }
}

// ============================================================
// OBSERVER — détecte la navigation dans Gmail (SPA)
// ============================================================

let lastUrl = location.href;

const observer = new MutationObserver(() => {
  const currentUrl = location.href;

  if (currentUrl !== lastUrl) {
    lastUrl = currentUrl;

    if (/[#/][A-Za-z0-9]{10,}/.test(currentUrl)) {
      onEmailOpened();
    }
  }
});

observer.observe(document.body, { childList: true, subtree: true });

console.log("[PhishGuard AI] Extension activée sur Gmail ✅");