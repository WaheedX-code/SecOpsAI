from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class PredictionRequest(BaseModel):
    features: dict = Field(
        ...,
        description="Network flow features as key-value pairs"
    )
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP")


class PredictionResponse(BaseModel):
    prediction: str
    confidence: float
    threat_score: float
    is_malicious: bool
    timestamp: datetime
    request_id: str


class HealthResponse(BaseModel):
    status: str
    model_version: str
    uptime_seconds: float


class TokenRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
