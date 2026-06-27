import json
import logging
from datetime import datetime, timezone
from typing import Any

from db.connection import get_db_conn

logger = logging.getLogger(__name__)

_FALLBACK_LOG = "data/audit.log"


def audit_log(
    event: str,
    username: str | None = None,
    ip_address: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    try:
        with get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO secopsai.audit_logs
                        (event, username, ip_address, details)
                    VALUES
                        (%s, %s, %s, %s)
                    """,
                    (
                        event,
                        username,
                        ip_address,
                        json.dumps(details) if details else None,
                    ),
                )
    except Exception as exc:
        logger.warning("PostgreSQL audit write failed, falling back to flat file: %s", exc)
        _flat_file_fallback(event, username, ip_address, details)


def _flat_file_fallback(
    event: str,
    username: str | None,
    ip_address: str | None,
    details: dict[str, Any] | None,
) -> None:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "username": username,
        "ip_address": ip_address,
        "details": details,
    }
    try:
        with open(_FALLBACK_LOG, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        logger.error("Flat-file audit fallback also failed: %s", exc)
