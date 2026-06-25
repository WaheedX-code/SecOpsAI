# tests/conftest.py
import pytest
import os

def pytest_configure(config):
    """Verify required env vars are present before any tests run."""
    required = ["JWT_SECRET_KEY", "ANALYST_PASSWORD", "ADMIN_PASSWORD"]
    missing = [k for k in required if not os.environ.get(k)]
    if missing:
        pytest.exit(
            f"Missing required environment variables: {', '.join(missing)}\n"
            f"Set them in .env or GitHub Secrets.",
            returncode=1
        )
