from fastapi import FastAPI
from src.api.routes import router
from src.api.schemas import HealthResponse

app = FastAPI(
    title="PhishGuard AI API",
    description="API de détection et prévention du phishing",
    version="1.0.0"
)

app.include_router(router, prefix="/api/v1")


@app.get("/health", response_model=HealthResponse)
async def health_check():
    return HealthResponse(
        status="ok",
        version="1.0.0"
    )