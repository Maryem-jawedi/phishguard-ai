// background.js — service worker PhishGuard avec Gmail API

const API_URL = "https://localhost:8443";

// ─────────────────────────────────────────────
// 1. Token PhishGuard
// ─────────────────────────────────────────────
async function getPhishGuardToken() {
  const r = await fetch(`${API_URL}/api/v1/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "username=analyst&password=analyst123",
  });
  const data = await r.json();
  return data.access_token;
}

// ─────────────────────────────────────────────
// 2. Token Gmail OAuth2
// ─────────────────────────────────────────────
async function getGmailToken() {
  return new Promise((resolve, reject) => {
    chrome.identity.getAuthToken({ interactive: true }, (token) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(token);
      }
    });
  });
}

// ─────────────────────────────────────────────
// 3. Recherche le messageId via sender + sujet
// ─────────────────────────────────────────────
async function findMessageId(subject, sender, gmailToken) {
  const queryParts = [];

  // Ajoute le sender s'il existe
  if (sender) {
    queryParts.push(`from:${sender}`);
  }

  // Ajoute le sujet seulement s'il est réel
  if (subject && subject !== "(aucun objet)" && subject.trim() !== "") {
    queryParts.push(`subject:"${subject}"`);
  }

  // Fallback total : dernier email de la boîte
  if (queryParts.length === 0) {
    queryParts.push("in:inbox");
  }

  // Limite à 7 jours pour éviter faux positifs
  queryParts.push("newer_than:7d");

  const query = encodeURIComponent(queryParts.join(" "));
  const url   = `https://www.googleapis.com/gmail/v1/users/me/messages?q=${query}&maxResults=3`;

  console.log("[PhishGuard] Query Gmail :", queryParts.join(" "));

  const r    = await fetch(url, {
    headers: { Authorization: `Bearer ${gmailToken}` },
  });
  const data = await r.json();

  if (!r.ok) {
    throw new Error(`Gmail search error: ${r.status} — ${JSON.stringify(data)}`);
  }

  if (!data.messages || data.messages.length === 0) {
    throw new Error(`Message introuvable — query: ${queryParts.join(" ")}`);
  }

  const messageId = data.messages[0].id;
  console.log("[PhishGuard] ✅ MessageId trouvé :", messageId);
  return messageId;
}

// ─────────────────────────────────────────────
// 4. Message ID → .eml brut
// ─────────────────────────────────────────────
async function fetchRawEmail(messageId, gmailToken) {
  const url = `https://www.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=raw`;
  console.log("[PhishGuard] Téléchargement .eml :", messageId);

  const r            = await fetch(url, {
    headers: { Authorization: `Bearer ${gmailToken}` },
  });
  const responseText = await r.text();

  if (!r.ok) {
    throw new Error(`Gmail API error: ${r.status} — ${responseText}`);
  }

  const data = JSON.parse(responseText);
  return data.raw;
}

// ─────────────────────────────────────────────
// 5. Envoyer le .eml à FastAPI
// ─────────────────────────────────────────────
async function analyzeWithPhishGuard(rawEml, phishGuardToken) {
  console.log("[PhishGuard] Envoi vers API FastAPI...");

  const r = await fetch(`${API_URL}/api/v1/analyze/extension`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${phishGuardToken}`,
    },
    body: JSON.stringify({ raw_eml: rawEml }),
  });

  if (!r.ok) {
    const text = await r.text();
    throw new Error(`PhishGuard API error: ${r.status} — ${text}`);
  }

  const result = await r.json();
  console.log("[PhishGuard] ✅ Résultat :", result);
  return result;
}

// ─────────────────────────────────────────────
// 6. Écouter les messages de content.js
// ─────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "ANALYZE_EMAIL") {
    console.log("[PhishGuard] Reçu — sujet :", msg.subject, "| sender :", msg.sender);

    (async () => {
      try {
        // A — deux tokens en parallèle
        const [gmailToken, phishGuardToken] = await Promise.all([
          getGmailToken(),
          getPhishGuardToken(),
        ]);
        console.log("[PhishGuard] ✅ Tokens récupérés");

        // B — sujet + sender → vrai messageId API
        const messageId = await findMessageId(msg.subject, msg.sender, gmailToken);

        // C — messageId → .eml brut
        const rawEml = await fetchRawEmail(messageId, gmailToken);

        // D — analyser
        const result = await analyzeWithPhishGuard(rawEml, phishGuardToken);

        sendResponse({ success: true, data: result });

      } catch (err) {
        console.error("[PhishGuard] ❌ Erreur :", err.message);
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
});