// ============================================================
// PhishGuard AI — popup.js
// ============================================================

// ── Vérifie si l'API est accessible ─────────────────────────
async function checkAPI(url) {
  try {
    const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
    return r.ok;
  } catch {
    return false;
  }
}

// ── Met à jour l'indicateur de statut API ───────────────────
async function updateAPIStatus() {
  const statusEl = document.getElementById("api-status");
  const stored = await chrome.storage.local.get("apiUrl");
  const url = stored.apiUrl || "http://localhost:8000";

  const ok = await checkAPI(url);

  statusEl.innerHTML = ok
    ? `<span class="dot green"></span>Connectée`
    : `<span class="dot red"></span>Hors ligne`;
}

// ── Charge les settings sauvegardés ─────────────────────────
async function loadSettings() {
  const data = await chrome.storage.local.get(["apiUrl", "emailCount"]);
  if (data.apiUrl) {
    document.getElementById("api-url").value = data.apiUrl;
  }
  document.getElementById("count").textContent = data.emailCount || 0;
}

// ── Sauvegarde les settings ──────────────────────────────────
document.getElementById("save-btn").addEventListener("click", async () => {
  const url = document.getElementById("api-url").value.trim();
  await chrome.storage.local.set({ apiUrl: url });

  const msg = document.getElementById("save-msg");
  msg.textContent = "✅ Sauvegardé !";
  setTimeout(() => msg.textContent = "", 2000);

  updateAPIStatus();
});

// ── Ouvre l'interface Gradio ─────────────────────────────────
document.getElementById("open-ui-btn").addEventListener("click", () => {
  chrome.tabs.create({ url: "http://localhost:7860" });
});

// ── Init ─────────────────────────────────────────────────────
loadSettings();
updateAPIStatus();