"""
SecOpsAI - Prometheus MetricsSink Adapter
"""

from __future__ import annotations

from api.metrics import (
    batch_predictions_total,
    batch_size_total,
    detection_by_type,
    detections_total,
    inference_latency,
    malicious_total,
    prediction_errors_total,
    unknown_features_total,
)


class PrometheusMetricsSink:
    """``MetricsSink`` implementation backed by the ``api.metrics`` registry."""

    def record_prediction(
        self,
        *,
        prediction: str,
        is_malicious: bool,
        latency_ms: float,
        source: str,
    ) -> None:
        detections_total.inc()
        detection_by_type.labels(threat_type=prediction).inc()
        inference_latency.observe(latency_ms)
        if is_malicious:
            malicious_total.inc()

    def record_batch(
        self,
        *,
        size: int,
        malicious_count: int,
        latency_ms: float,
        source: str,
    ) -> None:
        batch_predictions_total.inc()
        batch_size_total.inc(size)
        detections_total.inc(size)
        malicious_total.inc(malicious_count)
        inference_latency.observe(latency_ms)

    def record_error(self, *, error_type: str, source: str) -> None:
        prediction_errors_total.labels(error_type=error_type, source=source).inc()

    def record_unknown_features(self, *, count: int, source: str) -> None:
        unknown_features_total.labels(source=source).inc(count)
