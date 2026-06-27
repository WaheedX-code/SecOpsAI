import os
import logging
from contextlib import contextmanager
import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

def get_db_url() -> str | None:
    password = os.getenv("POSTGRES_PASSWORD")
    if not password:
        return None
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    db   = os.getenv("POSTGRES_DB", "secopsai")
    user = os.getenv("POSTGRES_USER", "secopsai")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


@contextmanager
def get_db_conn():
    url = get_db_url()
    if not url:
        raise RuntimeError("POSTGRES_PASSWORD not set — cannot connect to PostgreSQL")
    conn = psycopg2.connect(url, cursor_factory=RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
