"""
SecOpsAI — Production Detection API
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Optional

import joblib
import numpy as np
import redis
from fastapi import FastAPI, HTTPException, Security, Request, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.schemas import (
    PredictionRequest, PredictionResponse,
    HealthResponse, TokenRequest, TokenResponse
)

from api.metrics import (
    detections_total, malicious_total, detection_by_type,
    inference_latency, model_f1_score, metrics_endpoint
)

from api.middleware import (
    verify_token, create_token, require_admin, get_users, verify_password
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.api")

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecOpsAI Detection API",
    description="AI-powered network threat detection — Adversarial ML hardened",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Startup State ────────────────────────────────────────────────────────────
START_TIME = time.time()
MODEL = None
SCALER = None
LABEL_ENCODER = None
FEATURES = None
REDIS_CLIENT = None
_TEST_MODE = False


@app.on_event("startup")
async def startup():
    global MODEL, SCALER, LABEL_ENCODER, FEATURES, REDIS_CLIENT

    # In test mode, models may already be injected via patches, don't overwrite
    import api.main as self_module
    if getattr(self_module, '_TEST_MODE', False):
        logger.info("Test mode - skipping model load")
        return

    logger.info("Loading model artifacts...")
    try:
        MODEL = joblib.load("detection/models/xgboost_hardened.pkl")
        SCALER = joblib.load("detection/models/scaler.pkl")
        LABEL_ENCODER = joblib.load("detection/models/label_encoder.pkl")

        with open("detection/ablation_results.json") as f:
            ablation = json.load(f)
        FEATURES = [item["feature"] for item in ablation]

        logger.info(f"Model loaded — {len(FEATURES)} features")
    except Exception as e:
        logger.error(f"Failed to load model: {e}")

    try:
        REDIS_CLIENT = redis.from_url(
            os.getenv("REDIS_URL", "redis://localhost:6379")
        )
        REDIS_CLIENT.ping()
        logger.info("Redis connected")
    except Exception as e:
        logger.warning(f"Redis not available: {e}")


# ─── Rate Limiting ────────────────────────────────────────────────────────────

def check_rate_limit(request: Request, max_requests: int = 60, window: int = 60):
    """Token bucket rate limiting via Redis — 60 requests per minute per IP."""
    if not REDIS_CLIENT:
        return  # Skip if Redis unavailable

    client_ip = request.client.host
    key = f"rate_limit:{client_ip}"

    try:
        current = REDIS_CLIENT.get(key)
        if current is None:
            REDIS_CLIENT.setex(key, window, 1)
        elif int(current) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded — 60 requests per minute"
            )
        else:
            REDIS_CLIENT.incr(key)
    except HTTPException:
        raise
    except Exception:
        pass  # Don't block requests if Redis fails


# ─── Audit Logging ────────────────────────────────────────────────────────────

def audit_log(event: str, user: str, details: dict):
    """Structured audit log — every API action logged."""
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        "user": user,
        "details": details,
        "audit_id": str(uuid.uuid4())
    }
    logger.info(f"AUDIT: {json.dumps(entry)}")

    # In production this writes to PostgreSQL
    # For now it writes to audit log file
    with open("data/audit.log", "a") as f:
        f.write(json.dumps(entry) + "\n")


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """System health check — no auth required."""
    return HealthResponse(
        status="healthy" if MODEL else "degraded",
        model_version="xgboost_hardened_v1",
        uptime_seconds=round(time.time() - START_TIME, 2)
    )


@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login(request: Request, body: TokenRequest):
    """Authenticate and receive JWT token."""
    check_rate_limit(request, max_requests=10, window=60)

    user = get_users().get(body.username)
    if not user or not verify_password(body.password, user["password"]):
        audit_log("LOGIN_FAILED", body.username, {"ip": request.client.host})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    token = create_token(body.username, user["role"])
    audit_log("LOGIN_SUCCESS", body.username, {"ip": request.client.host})
    return TokenResponse(access_token=token)


@app.post("/detect", response_model=PredictionResponse, tags=["Detection"])
async def detect(
    request: Request,
    body: PredictionRequest,
    token: dict = Security(verify_token)
):
    """
    Run threat detection on network flow features.
    Requires valid JWT token.
    p99 latency target: <200ms
    """
    start = time.time()
    request_id = str(uuid.uuid4())
    check_rate_limit(request)

    if MODEL is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded"
        )

    try:
        # Build feature vector in correct order
        feature_vector = []
        for feat in FEATURES:
            val = body.features.get(feat, 0.0)
            feature_vector.append(float(val))

        X = np.array([feature_vector], dtype=np.float32)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        X_scaled = SCALER.transform(X)

        # Inference
        pred_class = MODEL.predict(X_scaled)[0]
        pred_proba = MODEL.predict_proba(X_scaled)[0]

        label = LABEL_ENCODER.inverse_transform([pred_class])[0]
        confidence = float(pred_proba.max())
        is_malicious = label != "Normal Traffic"
        threat_score = 1.0 - float(pred_proba[
            list(LABEL_ENCODER.classes_).index("Normal Traffic")
        ]) if "Normal Traffic" in LABEL_ENCODER.classes_ else confidence

        latency_ms = (time.time() - start) * 1000
        logger.info(f"Inference: {label} ({confidence:.3f}) in {latency_ms:.1f}ms")

        audit_log("DETECTION", token["sub"], {
            "request_id": request_id,
            "prediction": label,
            "confidence": round(confidence, 4),
            "latency_ms": round(latency_ms, 2),
            "source_ip": body.source_ip
        })

        return PredictionResponse(
            prediction=label,
            confidence=confidence,
            threat_score=threat_score,
            is_malicious=is_malicious,
            timestamp=datetime.utcnow(),
            request_id=request_id
        )

    except Exception as e:
        logger.error(f"Inference error: {e}")
        raise HTTPException(status_code=500, detail="Inference failed")

        # Record metrics
        detections_total.inc()
        inference_latency.observe(latency_ms)
        detection_by_type.labels(threat_type=label).inc()
        if is_malicious:
            malicious_total.inc()


@app.get("/model/info", tags=["Model"])
async def model_info(token: dict = Security(verify_token)):
    """Return model metadata and performance metrics."""
    try:
        with open("detection/ml_metrics.json") as f:
            ml_metrics = json.load(f)
        with open("detection/baseline_metrics.json") as f:
            baseline = json.load(f)
        with open("detection/adversarial_results_post.json") as f:
            adv_results = json.load(f)

        return {
            "model": "XGBoost + Adversarial Hardening",
            "ml_metrics": ml_metrics,
            "baseline_metrics": baseline,
            "improvement": round(
                ml_metrics["f1_macro"] - baseline["f1_macro"], 4
            ),
            "adversarial_results": adv_results
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/audit/logs", tags=["Admin"])
async def get_audit_logs(
    token: dict = Depends(require_admin)
):
    """Return recent audit logs — admin only."""
    try:
        with open("data/audit.log") as f:
            lines = f.readlines()[-50:]
        return {"logs": [json.loads(l) for l in lines]}
    except FileNotFoundError:
        return {"logs": []}

@app.get("/metrics", tags=["System"])
async def metrics():
    """Prometheus metrics endpoint"""
    return metrics_endpoint()
