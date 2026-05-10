# ============================================================
# PhishGuard AI — Dockerfile
# Image unique utilisée pour les deux services (API + UI)
# ============================================================

FROM python:3.10-slim

# ── Variables d'environnement ────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# ── Dépendances système (DNS, SSL, compilateurs pour certains packages) ──
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libssl-dev \
        dnsutils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Répertoire de travail ────────────────────────────────────
WORKDIR /app

# ── Copie des dépendances Python en premier (cache Docker) ──
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Copie du code source ─────────────────────────────────────
COPY src/           ./src/
COPY modeles_sauvegardes/ ./modeles_sauvegardes/
COPY features_contract.json .

# ── Port exposé par défaut (API) ─────────────────────────────
# Le service UI utilise le port 7860, défini dans docker-compose
EXPOSE 8000

# ── CMD par défaut : API FastAPI ─────────────────────────────
# Surchargé par le service "ui" dans docker-compose.yml
CMD ["uvicorn", "src.api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1"]