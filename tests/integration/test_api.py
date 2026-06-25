"""
SecOpsAI — API Integration Tests
"""

import pytest
import numpy as np
from unittest.mock import patch
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Test client with mocked model and injected test users."""
    # Reset user cache so env vars are used
    import api.middleware as mw
    mw._USERS = None

    with patch("api.main.MODEL") as mock_model, \
         patch("api.main.SCALER") as mock_scaler, \
         patch("api.main.LABEL_ENCODER") as mock_le, \
         patch("api.main.FEATURES", ["Flow Duration", "Total Fwd Packets"]), \
         patch("api.main.REDIS_CLIENT", None):

        mock_model.predict.return_value = np.array([0])
        mock_model.predict_proba.return_value = np.array([[0.95, 0.05]])
        mock_scaler.transform.return_value = np.array([[1.0, 2.0]])
        mock_le.inverse_transform.return_value = ["Normal Traffic"]
        mock_le.classes_ = ["Normal Traffic", "DoS"]

        from api.main import app
        with TestClient(app) as client:
            yield client

        mw._USERS = None


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert "status" in resp.json()


def test_login_success(client):
    resp = client.post("/auth/token", json={
        "username": "analyst", "password": "analyst123"
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password(client):
    resp = client.post("/auth/token", json={
        "username": "analyst", "password": "wrongpassword"
    })
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/auth/token", json={
        "username": "hacker", "password": "password"
    })
    assert resp.status_code == 401


def test_detect_requires_auth(client):
    resp = client.post("/detect", json={"features": {"Flow Duration": 100}})
    assert resp.status_code == 401


def test_detect_with_valid_token(client):
    token = client.post("/auth/token", json={
        "username": "analyst", "password": "analyst123"
    }).json()["access_token"]

    resp = client.post(
        "/detect",
        json={"features": {"Flow Duration": 100, "Total Fwd Packets": 50},
              "source_ip": "192.168.1.1"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "prediction" in data
    assert "confidence" in data
    assert "is_malicious" in data
    assert "request_id" in data


def test_detect_invalid_token(client):
    resp = client.post(
        "/detect",
        json={"features": {"Flow Duration": 100}},
        headers={"Authorization": "Bearer invalidtoken123"}
    )
    assert resp.status_code == 401


def test_model_info_requires_auth(client):
    resp = client.get("/model/info")
    assert resp.status_code == 401


def test_audit_logs_requires_admin(client):
    token = client.post("/auth/token", json={
        "username": "analyst", "password": "analyst123"
    }).json()["access_token"]
    resp = client.get("/audit/logs",
                      headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_audit_logs_admin_access(client):
    token = client.post("/auth/token", json={
        "username": "admin", "password": "admin123"
    }).json()["access_token"]
    resp = client.get("/audit/logs",
                      headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "logs" in resp.json()


def test_openapi_docs_available(client):
    resp = client.get("/docs")
    assert resp.status_code == 200


def test_metrics_endpoint(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert b"secopsai_detections_total" in resp.content
