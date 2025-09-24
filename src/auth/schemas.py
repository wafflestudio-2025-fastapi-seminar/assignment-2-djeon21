from pydantic import BaseModel, EmailStr

class TokenLoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenPairResponse(BaseModel):
    access_token: str
    refresh_token: str

class RefreshRequest(BaseModel):
    refresh_token: str

class SessionLoginRequest(BaseModel):
    email: EmailStr
    password: str
