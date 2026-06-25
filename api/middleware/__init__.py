import os
import uuid
import logging
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("secopsai.auth")

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "secopsai-dev-secret-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Users loaded lazily — never at import time
_USERS = None

def get_users() -> dict:
    global _USERS
    if _USERS is None:
        analyst_pw = os.getenv("ANALYST_PASSWORD")
        admin_pw = os.getenv("ADMIN_PASSWORD")

        if not analyst_pw or not admin_pw:
            raise RuntimeError(
                "ANALYST_PASSWORD and ADMIN_PASSWORD must be set. "
                "Check your .env file or Github secrets."
            )

        _USERS = {
            "analyst": {
                "password": pwd_context.hash(analyst_pw),
                "role": "analyst"
            },
            "admin": {
                "password": pwd_context.hash(admin_pw),
                "role": "admin"
            }
        }
    return _USERS


def reset_users():
    """Reset user cache — used in tests."""
    global _USERS
    _USERS = None


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_token(username: str, role: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": username,
        "role": role,
        "exp": expire,
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    try:
        payload = jwt.decode(
            credentials.credentials,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


def require_admin(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    token = verify_token(credentials)
    if token.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Requires admin role"
        )
    return token
