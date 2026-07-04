from __future__ import annotations
from typing import Protocol, runtime_checkable
@runtime_checkable
class MetricsSink(Protocol):
    """Interface for recording detection engine telemetry.
    Implementations should be lightweight, non-blocking, and must
    never propagate exceptions back to the inference engine. A
    telemetry backend becoming unavailable should never interrupt
    model inference.
    """
    def record_prediction(
        self,
        *,
        prediction: str,
        is_malicious: bool,
        latency_ms: float,
        source: str,
    ) -> None:
        """Record a completed prediction."""
        ...
    def record_batch(
        self,
        *,
        size: int,
        malicious_count: int,
        latency_ms: float,
        source: str,
    ) -> None:
        """Record a completed batch prediction."""
        ...
    def record_error(
        self,
        *,
        error_type: str,
        source: str,
    ) -> None:
        """Record an inference or validation error."""
        ...
    def record_unknown_features(
        self,
        *,
        count: int,
        source: str,
    ) -> None:
        """Record ignored feature names that are unknown to the model."""
        ...
class NullMetricsSink:
    """A `MetricsSink` implementation that discards all metrics.
    This is the default implementation used when no metrics backend
    is supplied, allowing the detection engine to operate without
    any telemetry dependencies.
    """
    def record_prediction(
        self,
        *,
        prediction: str,
        is_malicious: bool,
        latency_ms: float,
        source: str,
    ) -> None:
        pass
    def record_batch(
        self,
        *,
        size: int,
        malicious_count: int,
        latency_ms: float,
        source: str,
    ) -> None:
        pass
    def record_error(
        self,
        *,
        error_type: str,
        source: str,
    ) -> None:
        pass
    def record_unknown_features(
        self,
        *,
        count: int,
        source: str,
    ) -> None:
        pass

