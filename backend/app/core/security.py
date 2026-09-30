"""Authentication (JWT) and role-based access control.

Roles, lowest to highest: viewer < analyst < engineer < admin.
Passwords: PBKDF2-HMAC-SHA256 (stdlib), 600k iterations, per-user salt.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

ROLES = ["viewer", "analyst", "engineer", "admin"]
ITERATIONS = 600_000
bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, hash_b64 = stored.split("$")
    except ValueError:
        return False
    if algo != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
    return hmac.compare_digest(dk, base64.b64decode(hash_b64))


def create_token(username: str, role: str, secret: str, ttl_min: int) -> str:
    now = int(time.time())
    return jwt.encode({"sub": username, "role": role, "iat": now, "exp": now + ttl_min * 60, "iss": "acrs"},
                      secret, algorithm="HS256")


def decode_token(token: str, secret: str) -> dict:
    claims = jwt.decode(token, secret, algorithms=["HS256"], issuer="acrs")
    if claims.get("role") not in ROLES:
        raise jwt.InvalidTokenError("unknown role")
    return {"username": claims["sub"], "role": claims["role"]}


async def current_user(request: Request, creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    if creds is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        return decode_token(creds.credentials, request.app.state.config.jwt_secret)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"}) from None


def require(role: str):
    minimum = ROLES.index(role)

    async def dep(user: dict = Depends(current_user)) -> dict:
        if ROLES.index(user["role"]) < minimum:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{role}' or higher")
        return user

    return dep
