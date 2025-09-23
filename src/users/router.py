from typing import Annotated
from datetime import datetime, timezone
import os, jwt
from argon2 import PasswordHasher

from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status,
    HTTPException
)

from src.auth.router import _now_utc
from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import InvalidSessionException, BadAuthorizationHeaderException, InvalidTokenException, UnauthenticatedException

user_router = APIRouter(prefix="/users", tags=["users"])

ALGO = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_DEV_ONLY")

@user_router.post("/", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(u.get("email") == request.email for u in user_db):
        from src.common import CustomException
        raise CustomException(409, "ERR_005", "EMAIL ALREADY EXISTS")
    
    hashed = PasswordHasher().hash(request.password)
    new_id = (user_db[-1]["user_id"] + 1) if user_db else 1
    
    new_info = {
        "user_id": new_id,
        "email": request.email,
        "hashed_password": hashed,
        "name": request.name,
        "phone_number": request.phone_number,
        "height": request.height,
        "bio": request.bio,
    }
    user_db.append(new_info)
    
    return UserResponse(
        user_id=new_info["user_id"],
        email=new_info["email"],
        name=new_info["name"],
        phone_number=new_info["phone_number"],
        height=new_info["height"],
        bio=new_info["bio"],
    )
    
@user_router.get("/me", response_model=UserResponse)
def get_user_info(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
    sid: Annotated[str | None, Cookie(alias="sid")] = None,
) -> UserResponse:
    # Prefer session if provided; otherwise try Bearer token
    if sid:
        sess = session_db.get(sid)
        if not sess:
            raise InvalidTokenException()
        if _now_utc() >= sess["exp"]:
            raise InvalidTokenException()
        uid = sess["user_id"]
    elif authorization:
        parts = authorization.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise BadAuthorizationHeaderException()

        token = parts[1]
        # access tokens typically aren't in the blacklist, but check anyway
        if token in blocked_token_db:
            raise InvalidTokenException()
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            raise InvalidTokenException()
        try:
            uid = int(payload.get("sub"))
        except Exception:
            raise InvalidTokenException()
    else:
        raise UnauthenticatedException()

    user = next((u for u in user_db if u["user_id"] == uid), None)
    if not user:
        raise InvalidTokenException()

    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        phone_number=user["phone_number"],
        height=user["height"],
        bio=user.get("bio"),
    )
    
# @user_router.get("/me", response_model=UserResponse)
# def get_user_info(
#     authorization: Annotated[str | None, Header(alias="Authorization")] = None,
#     sid: Annotated[str | None, Cookie(alias="sid")] = None,
# ) -> UserResponse:
#     now = datetime.now(timezone.utc)
    
#     # Session-based authentication
#     if sid is not None:
#         sess = session_db.get(sid)
#         if sess is None:
#             raise InvalidSessionException()
        
#         if isinstance(sess, int):
#             user_id = sess
#         elif isinstance(sess, dict):
#             if "user_id" not in sess:
#                 raise InvalidSessionException()
#             user_id = int(sess["user_id"])
            
#             exp = sess.get("exp")
#             if exp is not None:
#                 if isinstance(exp, str):
#                     try:
#                         exp = datetime.fromisoformat(exp)
#                     except Exception:
#                         raise InvalidSessionException()
#                 elif isinstance(exp, (int, float)):
#                     exp = datetime.fromtimestamp(exp, tz=timezone.utc)
#                 if now >= exp:
#                     raise InvalidSessionException()
#         else:
#             raise InvalidSessionException()
            
#         user = next((u for u in user_db if u.get("user_id") == user_id), None)
#         if not user:
#             raise InvalidSessionException()
            
#         return UserResponse(
#             user_id=user["user_id"],
#             email=user["email"],
#             name=user["name"],
#             phone_number=user["phone_number"],
#             height=user["height"],
#             bio=user["bio"],
#         )
            
#     # Token-based authentication
#     if authorization:
#         parts = authorization.split(None, 1)
#         if len(parts) != 2 or parts[0].lower() != "bearer":
#             from src.users.errors import BadAuthorizationHeaderException
#             raise BadAuthorizationHeaderException()

#         token = parts[1]
#         if token in blocked_token_db:
#             from src.users.errors import InvalidTokenException
#             raise InvalidTokenException()

#         try:
#             payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
#         except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
#             from src.users.errors import InvalidTokenException
#             raise InvalidTokenException()

#         uid = int(payload.get("sub"))
#         user = next((u for u in user_db if u["user_id"] == uid), None)
#         if not user:
#             from src.users.errors import InvalidTokenException
#             raise InvalidTokenException()

#         return UserResponse(
#             user_id=user["user_id"],
#             email=user["email"],
#             name=user["name"],
#             phone_number=user["phone_number"],
#             height=user["height"],
#             bio=user.get("bio"),
#         )
        
#     raise UnauthenticatedException()