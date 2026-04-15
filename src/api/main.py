from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from datetime import timedelta

from src.api.routes import router
from src.api.schemas import HealthResponse
from src.api.auth import (
    authenticate_user, create_access_token,
    get_current_active_user,
    Token, ACCESS_TOKEN_EXPIRE_MINUTES
)
from fastapi.security import OAuth2PasswordRequestForm
from fastapi import HTTPException, status

app = FastAPI(
    title="PhishGuard AI API",
    description="API de détection et prévention du phishing — ENSI 2025/2026",
    version="1.0.0",
)

# CORS — permet à l'UI Gradio de contacter l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes analyse (protégées) ──────────────────────────────────
app.include_router(router, prefix="/api/v1")


# ── Route auth : obtenir un token JWT ──────────────────────────
@app.post("/api/v1/auth/token", response_model=Token, tags=["Authentification"])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        username=user.username,
        role=user.role,
    )


# ── Health check (public) ───────────────────────────────────────
@app.get("/health", response_model=HealthResponse, tags=["Système"])
async def health_check():
    return HealthResponse(status="ok", version="1.0.0")


# ── Route protégée : profil utilisateur connecté ───────────────
@app.get("/api/v1/auth/me", tags=["Authentification"])
async def get_me(current_user=Depends(get_current_active_user)):
    return {
        "username":  current_user.username,
        "full_name": current_user.full_name,
        "role":      current_user.role,
    }