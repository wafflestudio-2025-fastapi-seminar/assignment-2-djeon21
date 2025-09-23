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

from src.users.schemas import CreateUserRequest, UserResponse
from src.common.database import blocked_token_db, session_db, user_db
from src.users.errors import InvalidSessionException, BadAuthorizationHeaderException, InvalidTokenException, UnauthenticatedException

user_router = APIRouter(prefix="/users", tags=["users"])

ALGO = "HS256"
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_DEV_ONLY")

@user_router.post("/", status_code=status.HTTP_201_CREATED, response_model=UserResponse)
def create_user(request: CreateUserRequest) -> UserResponse:
    if any(u.get("email") == request.email for u in user_db):
        raise HTTPException(status_code=409, detail="EMAIL ALREADY EXISTS")
    
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
    now = datetime.now(timezone.utc)
    
    # Session-based authentication
    if sid is not None:
        sess = session_db.get(sid)
        if sess is None:
            raise InvalidSessionException()
        
        if isinstance(sess, int):
            user_id = sess
        elif isinstance(sess, dict):
            if "user_id" not in sess:
                raise InvalidSessionException()
            user_id = int(sess["user_id"])
            
            exp = sess.get("exp")
            if exp is not None:
                if isinstance(exp, str):
                    try:
                        exp = datetime.fromisoformat(exp)
                    except Exception:
                        raise InvalidSessionException()
                elif isinstance(exp, (int, float)):
                    exp = datetime.fromtimestamp(exp, tz=timezone.utc)
                if now >= exp:
                    raise InvalidSessionException()
        else:
            raise InvalidSessionException()
            
        user = next((u for u in user_db if u.get("user_id") == user_id), None)
        if not user:
            raise InvalidSessionException()
            
        return UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            phone_number=user["phone_number"],
            height=user["height"],
            bio=user["bio"],
        )
            
    # Token-based authentication
    if authorization:
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise BadAuthorizationHeaderException()

        token = parts[1]
        if token in blocked_token_db:
            raise InvalidTokenException()

        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGO])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            raise InvalidTokenException()

        sub = payload.get("sub")
        try:
            user_id = int(sub)
        except Exception:
            raise InvalidTokenException()

        user = next((u for u in user_db if u.get("user_id") == user_id), None)
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
        
    raise UnauthenticatedException()