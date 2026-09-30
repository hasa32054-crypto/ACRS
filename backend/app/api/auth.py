from fastapi import APIRouter, Depends, HTTPException, Request

from ..core.security import create_token, current_user, verify_password
from ..schemas.api import LoginIn, TokenOut
from .deps import store

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=TokenOut)
async def login(body: LoginIn, request: Request, st=Depends(store)):
    user = await st.get_user(body.username)
    if not user or not verify_password(body.password, user["password_hash"]):
        await st.audit(body.username, "LOGIN_FAILED", None, "invalid credentials")
        raise HTTPException(401, "Invalid username or password")
    cfg = request.app.state.config
    await st.audit(body.username, "LOGIN", None, "ok", metadata={"role": user["role"]})
    return TokenOut(access_token=create_token(user["username"], user["role"], cfg.jwt_secret, cfg.jwt_ttl_min),
                    role=user["role"], expires_in=cfg.jwt_ttl_min * 60)


@router.get("/me")
async def me(user: dict = Depends(current_user)):
    return user
