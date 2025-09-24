from fastapi import APIRouter
from fastapi import Cookie, status, Header, Response, status, Body
from datetime import datetime, timezone, timedelta
import os, jwt, secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
from typing import Annotated

from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import InvalidAccountException, UnauthenticatedException, BadAuthorizationHeaderException, InvalidTokenException
from src.auth.schemas import TokenLoginRequest, TokenPairResponse, SessionLoginRequest, RefreshRequest

auth_router = APIRouter(prefix="/auth", tags=["auth"])

SHORT_SESSION_LIFESPAN: int = 15
LONG_SESSION_LIFESPAN: int = 24 * 60

ALGO  ="HS256"
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_DEV_ONLY")

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _find_user_by_email(email: str) -> dict | None:
    return next((u for u in user_db if u.get("email") == email), None)

def _make_jwt(sub: str, minutes: int) -> str:
    now = _now_utc()
    payload = {"sub": sub, "iat": now, "exp": now + timedelta(minutes=minutes)}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGO)



@auth_router.post("/token", status_code=status.HTTP_200_OK, response_model=TokenPairResponse)
def issue_token(body: TokenLoginRequest) -> TokenPairResponse:
    user = _find_user_by_email(body.email)
    if not user:
        raise InvalidAccountException()
    try:
        PasswordHasher().verify(user["hashed_password"], body.password)
    except (VerifyMismatchError, InvalidHash):
        raise InvalidAccountException()
    
    sub = str(user["user_id"])
    access_token = _make_jwt(sub, SHORT_SESSION_LIFESPAN)
    refresh_token = _make_jwt(sub, LONG_SESSION_LIFESPAN)
    return TokenPairResponse(access_token=access_token, refresh_token=refresh_token)


@auth_router.post("/token/refresh", status_code=status.HTTP_200_OK, response_model=TokenPairResponse)
def refresh_token(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> TokenPairResponse:
    if authorization is None:
        raise UnauthenticatedException() 

    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise BadAuthorizationHeaderException()  

    refresh = parts[1]

    if refresh in blocked_token_db:
        raise InvalidTokenException() 

    try:
        payload = jwt.decode(refresh, JWT_SECRET, algorithms=[ALGO])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise InvalidTokenException() 

    sub = payload.get("sub")
    try:
        uid = int(sub)
    except Exception:
        raise InvalidTokenException()

    if not any(u.get("user_id") == uid for u in user_db):
        raise InvalidTokenException()

    exp_unix = float(payload["exp"])
    blocked_token_db[refresh] = exp_unix

    new_access  = _make_jwt(str(uid), SHORT_SESSION_LIFESPAN)
    new_refresh = _make_jwt(str(uid), LONG_SESSION_LIFESPAN)
    return TokenPairResponse(access_token=new_access, refresh_token=new_refresh)

@auth_router.delete("/token", status_code=status.HTTP_204_NO_CONTENT)
def revoke_refresh_token(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
):
    if authorization is None:
        raise UnauthenticatedException()  

    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise BadAuthorizationHeaderException()  

    refresh = parts[1]

    now_unix = _now_utc().timestamp()
    exp_block = blocked_token_db.get(refresh)
    if exp_block is not None and now_unix < float(exp_block):
        raise InvalidTokenException() 

    try:
        payload = jwt.decode(refresh, JWT_SECRET, algorithms=[ALGO])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        raise InvalidTokenException()  

    exp_unix = float(payload.get("exp"))
    blocked_token_db[refresh] = exp_unix

    return Response(status_code=status.HTTP_204_NO_CONTENT)

@auth_router.post("/session", status_code=status.HTTP_200_OK)
def session_login(body: SessionLoginRequest, response: Response):
    user = next((u for u in user_db if u.get("email") == body.email), None)
    if not user:
        raise InvalidAccountException()

    try:
        PasswordHasher().verify(user["hashed_password"], body.password)
    except Exception:
        raise InvalidAccountException()

    sid = secrets.token_urlsafe(32)
    exp = datetime.now(timezone.utc) + timedelta(minutes=LONG_SESSION_LIFESPAN)
    session_db[sid] = {"user_id": user["user_id"], "exp": exp}

    response.set_cookie(
        key="sid",
        value=sid,
        httponly=True,
        samesite="lax",
        max_age=LONG_SESSION_LIFESPAN * 60,
        secure=False,  
        path="/",
    )

    return {"ok": True}

@auth_router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
def session_logout(
    response: Response,
    sid: Annotated[str | None, Cookie(alias="sid")] = None,
):
    response.delete_cookie(key="sid", path="/", samesite="lax", secure=False)

    if sid:
        session_db.pop(sid, None)

    response.status_code = status.HTTP_204_NO_CONTENT
    return