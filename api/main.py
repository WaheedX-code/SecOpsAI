"""
SecOpsAI - Production Detection API
"""

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import redis
from fastapi import Depends, FastAPI, HTTPException, Request, Security, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.audit import audit_log
from api.metrics import metrics_endpoint
from api.metrics_sink import PrometheusMetricsSink
from api.middleware import (
    create_token,
    get_users,
    require_admin,
    verify_password,
    verify_token,
)
from api.schemas import (
    HealthResponse,
    PredictionRequest,
    PredictionResponse,
    TokenRequest,
    TokenResponse,
)
from detection.detector import DetectionService
from detection.exceptions import (
    DetectionError,
    FeatureValidationError,
    ModelNotLoadedError,
    PredictionError,
)
from detection.model_loader import ModelLoader
from detection.models import PredictionContext

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.api")

_NORMAL_LABEL = "Normal Traffic"


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load model artifacts and connect to Redis on startup.

    State is attached to ``app.state`` rather than module-level
    globals, so it can be overridden per-app-instance in tests without
    a ``_TEST_MODE`` flag, and so multiple app instances (e.g. in
    tests) don't share mutable module state.
    """
    app.state.detector = None
    app.state.redis_client = None
    app.state.start_time = time.time()

    logger.info("Loading model artifacts")
    try:
        loader = ModelLoader()
        loader.load()
        detector = DetectionService(loader, metrics=PrometheusMetricsSink())
        warmup_latency_ms = detector.warmup()
        app.state.detector = detector
        logger.info(
            "Model loaded features=%d warmup_latency_ms=%.1f",
            len(loader.get_features()),
            warmup_latency_ms,
        )
    except DetectionError:
        logger.exception("Failed to load model")

    try:
        redis_client = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379"))
        redis_client.ping()
        app.state.redis_client = redis_client
        logger.info("Redis connected")
    except Exception:
        logger.warning("Redis not available", exc_info=True)

    yield


app = FastAPI(
    title="SecOpsAI Detection API",
    description="AI-powered network threat detection — Adversarial ML hardened",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Dependencies ─────────────────────────────────────────────────────────────

def get_detector(request: Request) -> DetectionService:
    """Resolve the request-scoped ``DetectionService`` from app state.

    Raises:
        HTTPException: 503 if the model failed to load at startup.
    """
    detector = request.app.state.detector
    if detector is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
    return detector


# ─── Exception Handlers ───────────────────────────────────────────────────────
# Registered once here rather than repeated per-endpoint try/except blocks.
# Route bodies let DetectionError subtypes propagate; FastAPI dispatches to
# the matching handler below.

@app.exception_handler(FeatureValidationError)
async def handle_feature_validation_error(request: Request, exc: FeatureValidationError):
    logger.warning("feature_validation_failed path=%s detail=%s", request.url.path, exc)
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.exception_handler(ModelNotLoadedError)
async def handle_model_not_loaded_error(request: Request, exc: ModelNotLoadedError):
    logger.error("model_not_loaded path=%s detail=%s", request.url.path, exc)
    return JSONResponse(status_code=503, content={"detail": "Model not loaded"})


@app.exception_handler(PredictionError)
async def handle_prediction_error(request: Request, exc: PredictionError):
    logger.error("prediction_failed path=%s detail=%s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Inference failed"})


# ─── Rate Limiting ────────────────────────────────────────────────────────────

def check_rate_limit(request: Request, max_requests: int = 60, window: int = 60):
    """Token bucket rate limiting via Redis — 60 requests per minute per IP."""
    redis_client = request.app.state.redis_client
    if not redis_client:
        return  # Skip if Redis unavailable

    client_ip = request.client.host
    key = f"rate_limit:{client_ip}"

    try:
        current = redis_client.get(key)
        if current is None:
            redis_client.setex(key, window, 1)
        elif int(current) >= max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded — 60 requests per minute"
            )
        else:
            redis_client.incr(key)
    except HTTPException:
        raise
    except Exception:
        pass  # Don't block requests if Redis fails

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health(request: Request):
    """System health check — no auth required."""
    detector: DetectionService | None = request.app.state.detector
    if detector is None:
        start_time = request.app.state.start_time
        return HealthResponse(
            status="degraded",
            ready=False,
            model_loaded=False,
            model_version="unknown",
            feature_count=0,
            num_classes=0,
            normal_label=_NORMAL_LABEL,
            started_at=datetime.fromtimestamp(start_time, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            uptime_seconds=round(time.time() - start_time, 2),
        )
    return HealthResponse(**detector.health())


@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
async def login(request: Request, body: TokenRequest):
    """Authenticate and receive JWT token."""
    check_rate_limit(request, max_requests=10, window=60)

    user = get_users().get(body.username)
    if not user or not verify_password(body.password, user["password"]):
        _audit_login(request, body.username, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )

    token = create_token(body.username, user["role"])
    _audit_login(request, body.username, success=True)
    return TokenResponse(access_token=token)


def _audit_login(request: Request, username: str, *, success: bool) -> None:
    """Record a login attempt, shared by the success and failure paths."""
    event = "LOGIN_SUCCESS" if success else "LOGIN_FAILED"
    ip = request.client.host
    audit_log(event, username=username, ip_address=ip, details={"ip": ip})


@app.post("/detect", response_model=PredictionResponse, tags=["Detection"])
async def detect(
    request: Request,
    body: PredictionRequest,
    token: dict = Security(verify_token),
    detector: DetectionService = Depends(get_detector),
):
    """
    Run threat detection on network flow features.
    Requires valid JWT token.
    p99 latency target: <200ms
    """
    check_rate_limit(request)

    context = PredictionContext(
        source="rest_api",
        metadata={
            "source_ip": body.source_ip,
            "destination_ip": body.destination_ip,
            "client_ip": request.client.host,
            "username": token["sub"],
        },
    )

    # FeatureValidationError / ModelNotLoadedError / PredictionError propagate
    # to the exception handlers registered above.
    result = detector.predict(body.features, context=context)

    audit_log("DETECTION", username=token["sub"], ip_address=body.source_ip, details={
        "request_id": result.request_id,
        "prediction": result.prediction,
        "confidence": round(result.confidence, 4),
        "source_ip": body.source_ip,
        "model_version": result.model_version,
    })

    return PredictionResponse(
        prediction=result.prediction,
        confidence=result.confidence,
        threat_score=result.threat_score,
        is_malicious=result.is_malicious,
        timestamp=result.timestamp,
        request_id=result.request_id,
        model_version=result.model_version,
    )


@app.get("/model/info", tags=["Model"])
async def model_info(
    token: dict = Security(verify_token),
    detector: DetectionService = Depends(get_detector),
):
    """Return model metadata and performance metrics."""
    info = detector.model_info()

    try:
        reports = {
            name: _read_json(path)
            for name, path in info["metrics_paths"].items()
        }
        ml_metrics = reports["ml_metrics"]
        baseline = reports["baseline_metrics"]

        return {
            **info,
            "ml_metrics": ml_metrics,
            "baseline_metrics": baseline,
            "improvement": round(
                ml_metrics["f1_macro"] - baseline["f1_macro"], 4
            ),
            "adversarial_results": reports["adversarial_results"],
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _read_json(path) -> dict:
    """Read and parse a single JSON report file."""
    with open(path) as f:
        return json.load(f)

@app.get("/audit/logs", tags=["Admin"])
async def get_audit_logs(
    limit: int = 50,
    offset: int = 0,
    event: str | None = None,
    username: str | None = None,
    token: dict = Depends(require_admin),
):
    """Return audit logs from PostgreSQL — admin only. Falls back to flat file."""
    from db.connection import get_db_conn

    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                filters, params = [], []
                if event:
                    filters.append("event = %s")
                    params.append(event)
                if username:
                    filters.append("username = %s")
                    params.append(username)

                where = ("WHERE " + " AND ".join(filters)) if filters else ""
                params += [limit, offset]

                cur.execute(
                    f"""
                    SELECT audit_id, timestamp, event, username,
                           ip_address, details
                    FROM secopsai.audit_logs
                    {where}
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                    """,
                    params,
                )
                rows = cur.fetchall()

        return {"source": "postgresql", "count": len(rows), "logs": rows}

    except Exception as exc:
        logger.warning("PostgreSQL query failed, falling back to flat file: %s", exc)
        try:
            with open("data/audit.log") as f:
                lines = f.readlines()
            records = []
            for line in lines:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            page = records[offset: offset + limit]
            return {"source": "flat_file", "count": len(page), "logs": page}
        except FileNotFoundError:
            return {"source": "flat_file", "count": 0, "logs": []}

@app.get("/metrics", tags=["System"])
async def metrics():
    """Prometheus metrics endpoint"""
    return metrics_endpoint()
