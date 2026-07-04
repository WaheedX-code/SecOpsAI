"""
SecOpsAI Detection Domain Models
These models represent the output of the inference engine.
They are intentionally independent of FastAPI.
"""
from _future_ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

def _new_request_id() --> str:      # Generate a default correlation ID when a caller doesn't supply one
    return str(uuid.uuid4())

@dataclass(frozen=True, slots=True)
class PredictionContext:
    request_id: str = fieldd(default_factory=_new_request_id)
    pipeline_id: str | None = None
    source: str = "Unknown"
    metadata: Mapping[str, Any] = field(default_factory=dict)

@dataclass(frozen=True, slots=True)
class DetectionResult:
    """
    Result returned by DetectionService.
    """

    prediction: str
    confidence: float
    threat_score: float
    is_malicious: bool
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
