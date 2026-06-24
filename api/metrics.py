"""
SecOpsAI — Prometheus Metrics
Exposes detection metrics for Grafana dashboard.
"""

from prometheus_client import Counter, Histogram, Gauge, generate_latest
from fastapi import Response

# ─── Metrics ──────────────────────────────────────────────────────────────────

detections_total = Counter(
    'secopsai_detections_total',
    'Total number of detection requests'
)

malicious_total = Counter(
    'secopsai_malicious_total',
    'Total number of malicious detections'
)

detection_by_type = Counter(
    'secopsai_detection_by_type',
    'Detections broken down by threat type',
    ['threat_type']
)

inference_latency = Histogram(
    'secopsai_inference_latency_ms',
    'Inference latency in milliseconds',
    buckets=[10, 25, 50, 100, 150, 200, 500]
)

model_f1_score = Gauge(
    'secopsai_model_f1_score',
    'Current model F1 score'
)

inference_latency_p99 = Gauge(
    'secopsai_inference_latency_p99',
    'p99 inference latency in milliseconds'
)


def metrics_endpoint():
    """Expose metrics for Prometheus scraping."""
    return Response(
        content=generate_latest(),
        media_type="text/plain"
    )

