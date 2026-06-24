"""
SecOpsAI — Grafana Setup Script
"""

import json
import time
import requests
import os
from dotenv import load_dotenv

load_dotenv()

GRAFANA_URL = "http://localhost:3000"
GRAFANA_USER = "admin"
GRAFANA_PASSWORD = os.getenv("GRAFANA_PASSWORD", "secopsai123")
AUTH = (GRAFANA_USER, GRAFANA_PASSWORD)


def wait_for_grafana():
    """Wait until Grafana is ready."""
    print("Waiting for Grafana to start...")
    for i in range(30):
        try:
            resp = requests.get(f"{GRAFANA_URL}/api/health", timeout=5)
            if resp.status_code == 200:
                print("✅ Grafana is ready")
                return True
        except Exception:
            pass
        time.sleep(2)
        print(f"  Retrying... ({i+1}/30)")
    return False


def create_prometheus_datasource():
    """Add Prometheus as a datasource."""
    datasource = {
        "name": "Prometheus",
        "type": "prometheus",
        "url": "http://prometheus:9090",
        "access": "proxy",
        "isDefault": True
    }

    # Check if already exists
    resp = requests.get(
        f"{GRAFANA_URL}/api/datasources/name/Prometheus",
        auth=AUTH
    )
    if resp.status_code == 200:
        print("✅ Prometheus datasource already exists")
        return resp.json()["id"]

    resp = requests.post(
        f"{GRAFANA_URL}/api/datasources",
        json=datasource,
        auth=AUTH
    )
    if resp.status_code in (200, 201):
        print("✅ Prometheus datasource created")
        return resp.json()["datasource"]["id"]
    else:
        print(f"❌ Failed to create datasource: {resp.text}")
        return None


def create_dashboard(datasource_id):
    """Create the SecOpsAI SOC dashboard."""
    dashboard = {
        "dashboard": {
            "title": "SecOpsAI — SOC Dashboard",
            "uid": "secopsai-main",
            "schemaVersion": 38,
            "version": 1,
            "refresh": "30s",
            "tags": ["secopsai", "soc"],
            "panels": [
                {
                    "id": 1,
                    "title": "Total Detections (24h)",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
                    "datasource": "Prometheus",
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 10},
                                    {"color": "red", "value": 50}
                                ]
                            }
                        }
                    },
                    "options": {
                        "colorMode": "background",
                        "reduceOptions": {"calcs": ["lastNotNull"]}
                    },
                    "targets": [{
                        "expr": "increase(secopsai_detections_total[24h])",
                        "refId": "A"
                    }]
                },
                {
                    "id": 2,
                    "title": "Malicious Detections (24h)",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 0},
                    "datasource": "Prometheus",
                    "fieldConfig": {
                        "defaults": {
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "red", "value": 1}
                                ]
                            }
                        }
                    },
                    "options": {
                        "colorMode": "background",
                        "reduceOptions": {"calcs": ["lastNotNull"]}
                    },
                    "targets": [{
                        "expr": "increase(secopsai_malicious_total[24h])",
                        "refId": "A"
                    }]
                },
                {
                    "id": 3,
                    "title": "Inference Latency p99 (ms)",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 12, "y": 0},
                    "datasource": "Prometheus",
                    "fieldConfig": {
                        "defaults": {
                            "unit": "ms",
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "green", "value": None},
                                    {"color": "yellow", "value": 100},
                                    {"color": "red", "value": 200}
                                ]
                            }
                        }
                    },
                    "options": {
                        "colorMode": "value",
                        "reduceOptions": {"calcs": ["lastNotNull"]}
                    },
                    "targets": [{
                        "expr": "histogram_quantile(0.99, secopsai_inference_latency_ms_bucket)",
                        "refId": "A"
                    }]
                },
                {
                    "id": 4,
                    "title": "Model F1 Score",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 18, "y": 0},
                    "datasource": "Prometheus",
                    "fieldConfig": {
                        "defaults": {
                            "unit": "percentunit",
                            "min": 0,
                            "max": 1,
                            "color": {"mode": "thresholds"},
                            "thresholds": {
                                "steps": [
                                    {"color": "red", "value": None},
                                    {"color": "yellow", "value": 0.5},
                                    {"color": "green", "value": 0.8}
                                ]
                            }
                        }
                    },
                    "options": {
                        "colorMode": "background",
                        "reduceOptions": {"calcs": ["lastNotNull"]}
                    },
                    "targets": [{
                        "expr": "secopsai_model_f1_score",
                        "refId": "A"
                    }]
                },
                {
                    "id": 5,
                    "title": "Detection Rate Over Time",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 4},
                    "datasource": "Prometheus",
                    "targets": [
                        {
                            "expr": "rate(secopsai_detections_total[5m])",
                            "legendFormat": "Total",
                            "refId": "A"
                        },
                        {
                            "expr": "rate(secopsai_malicious_total[5m])",
                            "legendFormat": "Malicious",
                            "refId": "B"
                        }
                    ]
                },
                {
                    "id": 6,
                    "title": "Inference Latency Over Time",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 4},
                    "datasource": "Prometheus",
                    "fieldConfig": {
                        "defaults": {"unit": "ms"}
                    },
                    "targets": [{
                        "expr": "histogram_quantile(0.99, rate(secopsai_inference_latency_ms_bucket[5m]))",
                        "legendFormat": "p99 Latency",
                        "refId": "A"
                    }]
                },
                {
                    "id": 7,
                    "title": "Threat Type Distribution",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 24, "x": 0, "y": 12},
                    "datasource": "Prometheus",
                    "targets": [{
                        "expr": "rate(secopsai_detection_by_type_total[5m])",
                        "legendFormat": "{{threat_type}}",
                        "refId": "A"
                    }]
                }
            ]
        },
        "folderId": 0,
        "overwrite": True
    }

    resp = requests.post(
        f"{GRAFANA_URL}/api/dashboards/db",
        json=dashboard,
        auth=AUTH
    )
    if resp.status_code in (200, 201):
        print("✅ SOC Dashboard created")
        print(f"   URL: {GRAFANA_URL}/d/secopsai-main")
        return True
    else:
        print(f"❌ Failed to create dashboard: {resp.text}")
        return False


if __name__ == "__main__":
    print("\nSecOpsAI — Grafana Setup")
    print("=" * 40)

    if not wait_for_grafana():
        print("❌ Grafana not available")
        exit(1)

    datasource_id = create_prometheus_datasource()
    create_dashboard(datasource_id)

    print("\n✅ Grafana setup complete")
    print(f"   Dashboard: {GRAFANA_URL}/d/secopsai-main")
    print(f"   Login: admin / {GRAFANA_PASSWORD}")
