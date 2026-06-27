import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# ─── Config ───────────────────────────────────────────────────────────────────
WAZUH_HOST = os.getenv("WAZUH_HOST", "localhost")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "514"))
WAZUH_PROTOCOL = os.getenv("WAZUH_PROTOCOL", "udp").lower()  # "udp" or "tcp"
WAZUH_ENABLED = os.getenv("WAZUH_ENABLED", "false").lower() == "true"

# Syslog facility/severity — LOG_LOCAL0 | LOG_ALERT = 161
SYSLOG_PRIORITY = 161


# ─── Syslog Formatter ─────────────────────────────────────────────────────────

def _build_syslog_message(alert: dict[str, Any]) -> str:
    """
    Format a SecOpsAI alert as a syslog message Wazuh can parse.
    Uses CEF-style key=value pairs so Wazuh rules can extract fields.
    """
    timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    hostname = socket.gethostname()

    # Core alert fields
    prediction  = alert.get("prediction", "Unknown")
    confidence  = alert.get("confidence", 0.0)
    threat_score = alert.get("threat_score", 0.0)
    is_malicious = alert.get("is_malicious", False)
    source_ip   = alert.get("source_ip", "unknown")
    request_id  = alert.get("request_id", "unknown")
    username    = alert.get("username", "unknown")
    latency_ms  = alert.get("latency_ms", 0.0)

    # Wazuh severity mapping
    severity = _map_severity(confidence, is_malicious)

    payload = (
        f"SecOpsAI: "
        f"severity={severity} "
        f"prediction={prediction} "
        f"confidence={confidence:.4f} "
        f"threat_score={threat_score:.4f} "
        f"is_malicious={is_malicious} "
        f"source_ip={source_ip} "
        f"analyst={username} "
        f"request_id={request_id} "
        f"latency_ms={latency_ms:.2f}"
    )

    return f"<{SYSLOG_PRIORITY}>{timestamp} {hostname} secopsai: {payload}"


def _map_severity(confidence: float, is_malicious: bool) -> str:
    """Map confidence + malicious flag to Wazuh-friendly severity label."""
    if not is_malicious:
        return "LOW"
    if confidence >= 0.95:
        return "CRITICAL"
    if confidence >= 0.80:
        return "HIGH"
    if confidence >= 0.60:
        return "MEDIUM"
    return "LOW"


# ─── Transport ────────────────────────────────────────────────────────────────

def _send_udp(message: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(message.encode("utf-8"), (WAZUH_HOST, WAZUH_PORT))


def _send_tcp(message: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(5)
        sock.connect((WAZUH_HOST, WAZUH_PORT))
        sock.sendall((message + "\n").encode("utf-8"))


# ─── Public Interface ─────────────────────────────────────────────────────────

def forward_to_wazuh(alert: dict[str, Any]) -> bool:
    """
    Forward a SecOpsAI alert to Wazuh via syslog.
    Returns True on success, False on failure.
    Silently skips if WAZUH_ENABLED is not set to true.
    """
    if not WAZUH_ENABLED:
        logger.debug("Wazuh forwarding disabled — set WAZUH_ENABLED=true to enable")
        return False

    try:
        message = _build_syslog_message(alert)

        if WAZUH_PROTOCOL == "tcp":
            _send_tcp(message)
        else:
            _send_udp(message)

        logger.info(
            "Wazuh alert forwarded: prediction=%s confidence=%.4f source_ip=%s",
            alert.get("prediction"),
            alert.get("confidence", 0.0),
            alert.get("source_ip"),
        )
        return True

    except Exception as exc:
        logger.warning("Wazuh forward failed: %s", exc)
        return False
