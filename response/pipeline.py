import json
import logging
import os
import uuid
from datetime import datetime
from typing import Optional
from response.wazuh_forwarder import forward_to_wazuh

import requests
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s"
)
logger = logging.getLogger("secopsai.response")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")


# ─── Enrichment ───────────────────────────────────────────────────────────────

def enrich_virustotal(ip: str) -> dict:
    """Look up IP reputation on VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        logger.warning("No VirusTotal API key — skipping enrichment")
        return {"source": "virustotal", "status": "skipped", "ip": ip}

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(url, headers=headers, timeout=10)

        if resp.status_code == 200:
            data = resp.json()
            stats = data.get("data", {}).get("attributes", {}).get(
                "last_analysis_stats", {}
            )
            return {
                "source": "virustotal",
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": data.get("data", {}).get(
                    "attributes", {}
                ).get("reputation", 0)
            }
        else:
            return {"source": "virustotal", "status": f"error_{resp.status_code}", "ip": ip}

    except Exception as e:
        logger.error(f"VirusTotal error: {e}")
        return {"source": "virustotal", "status": "error", "ip": ip}


def enrich_shodan(ip: str) -> dict:
    """Look up host info on Shodan."""
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    if not SHODAN_API_KEY:
        logger.warning("No Shodan API key — skipping enrichment")
        return {"source": "shodan", "status": "skipped", "ip": ip}

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
        resp = requests.get(url, timeout=10)

        if resp.status_code == 200:
            data = resp.json()
            return {
                "source": "shodan",
                "ip": ip,
                "org": data.get("org", "unknown"),
                "country": data.get("country_name", "unknown"),
                "open_ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys())[:5]
            }
        else:
            return {"source": "shodan", "status": f"error_{resp.status_code}", "ip": ip}

    except Exception as e:
        logger.error(f"Shodan error: {e}")
        return {"source": "shodan", "status": "error", "ip": ip}


# ─── Notification ─────────────────────────────────────────────────────────────

def send_slack_alert(alert: dict, enrichment: dict) -> bool:
    """Send enriched alert to Slack webhook."""
    if not SLACK_WEBHOOK_URL:
        logger.warning("No Slack webhook — logging alert locally")
        logger.info(f"ALERT: {json.dumps(alert, indent=2)}")
        return False

    vt = enrichment.get("virustotal", {})
    shodan = enrichment.get("shodan", {})

    severity = "HIGH" if alert.get("confidence", 0) > 0.9 else "MEDIUM"

    message = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{severity} — SecOpsAI Threat Detection"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat:*\n{alert.get('prediction')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence:*\n{alert.get('confidence', 0):.1%}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source IP:*\n{alert.get('source_ip', 'unknown')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Threat Score:*\n{alert.get('threat_score', 0):.3f}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*VirusTotal:* {vt.get('malicious', 'N/A')} malicious detections\n"
                        f"*Shodan:* {shodan.get('org', 'N/A')} — "
                        f"Ports: {shodan.get('open_ports', 'N/A')}"
                    )
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Request ID:* `{alert.get('request_id')}`\n"
                            f"*Timestamp:* {alert.get('timestamp')}"
                }
            }
        ]
    }

    try:
        resp = requests.post(
            SLACK_WEBHOOK_URL,
            json=message,
            timeout=10
        )
        if resp.status_code == 200:
            logger.info("Slack alert sent successfully")
            return True
        else:
            logger.error(f"Slack error: {resp.status_code}")
            return False
    except Exception as e:
        logger.error(f"Slack error: {e}")
        return False


# ─── Containment ──────────────────────────────────────────────────────────────

def mock_firewall_block(ip: str, reason: str) -> dict:
    """
    Mock firewall containment action.
    In production this calls your firewall API or pfSense/iptables.
    """
    action_id = str(uuid.uuid4())
    action = {
        "action_id": action_id,
        "action": "firewall_block",
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "executed",
        "mock": True,
        "command": f"iptables -A INPUT -s {ip} -j DROP"
    }

    logger.info(f"CONTAINMENT: {json.dumps(action)}")

    # Log containment action
    with open("data/containment.log", "a") as f:
        f.write(json.dumps(action) + "\n")

    return action


# ─── Main Pipeline ────────────────────────────────────────────────────────────

def process_alert(detection_response: dict) -> dict:
    """
    Full alert pipeline:
    Detection result → Enrichment → Notification → Containment
    """
    pipeline_id = str(uuid.uuid4())
    logger.info(f"Processing alert {pipeline_id}")

    prediction = detection_response.get("prediction", "Unknown")
    confidence = detection_response.get("confidence", 0)
    source_ip = detection_response.get("source_ip", "unknown")
    is_malicious = detection_response.get("is_malicious", False)

    if not is_malicious:
        logger.info(f"Benign traffic — no alert needed ({prediction})")
        return {"status": "benign", "pipeline_id": pipeline_id}

    logger.info(f"Malicious traffic detected: {prediction} ({confidence:.1%})")

    # Step 1 — Enrich
    enrichment = {}
    if source_ip and source_ip != "unknown":
        logger.info("Enriching with VirusTotal and Shodan...")
        enrichment["virustotal"] = enrich_virustotal(source_ip)
        enrichment["shodan"] = enrich_shodan(source_ip)

    # Step 2 — Alert
    alert_payload = {
        **detection_response,
        "pipeline_id": pipeline_id
    }
    send_slack_alert(alert_payload, enrichment)

    # Step 2b — Wazuh SIEM forwarding
    forward_to_wazuh({
        "prediction": prediction,
        "confidence": confidence,
        "threat_score": detection_response.get("threat_score", 0.0),
        "is_malicious": is_malicious,
        "source_ip": source_ip,
        "request_id": detection_response.get("request_id", "unknown"),
        "username": detection_response.get("username", "unknown"),
        "latency_ms": detection_response.get("latency_ms", 0.0),
        "pipeline_id": pipeline_id,
    })

    # Step 3 — Containment (auto-block if confidence > 95%)
    containment = None
    if confidence > 0.95 and source_ip and source_ip != "unknown":
        logger.info(f"High confidence ({confidence:.1%}) — triggering containment")
        containment = mock_firewall_block(
            ip=source_ip,
            reason=f"SecOpsAI detected {prediction} with {confidence:.1%} confidence"
        )

    result = {
        "pipeline_id": pipeline_id,
        "status": "processed",
        "prediction": prediction,
        "confidence": confidence,
        "enrichment": enrichment,
        "containment": containment,
        "timestamp": datetime.utcnow().isoformat()
    }

    # Save to alerts log
    with open("data/alerts.log", "a") as f:
        f.write(json.dumps(result) + "\n")

    logger.info(f"Alert pipeline complete: {pipeline_id}")
    return result


# ─── Test ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Simulate a malicious detection firing
    test_detection = {
        "prediction": "DoS",
        "confidence": 0.97,
        "threat_score": 0.97,
        "is_malicious": True,
        "source_ip": "192.168.1.100",
        "request_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat()
    }

    logger.info("Testing alert pipeline with simulated DoS detection...")
    result = process_alert(test_detection)
    logger.info(f"Pipeline result: {json.dumps(result, indent=2)}")
