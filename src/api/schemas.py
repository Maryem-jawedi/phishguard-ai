from pydantic import BaseModel
from typing import Optional


# -- Requêtes entrantes

class EmailAnalysisRequest(BaseModel):
    raw_email: str


class URLAnalysisRequest(BaseModel):
    url: str


# -- Réponses sortantes

class EmailAnalysisResponse(BaseModel):
    is_phishing: Optional[int] = None
    confidence: Optional[float] = None
    features: dict
    suspicious_elements: list[str]
    report: str
    explanation: Optional[dict] = None


class URLAnalysisResponse(BaseModel):
    url: str
    is_phishing: Optional[int] = None
    confidence: Optional[float] = None
    features: dict
    suspicious_elements: list[str]


class HealthResponse(BaseModel):
    status: str
    version: str