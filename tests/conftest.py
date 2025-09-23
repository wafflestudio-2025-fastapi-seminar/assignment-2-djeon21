from typing import Generator

import pytest
from fastapi.testclient import TestClient

from src.main import app
from src.common.database import user_db
from src.common.database import blocked_token_db
from src.common.database import session_db

@pytest.fixture
def client() -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client
    
    blocked_token_db.clear()
    session_db.clear()
    user_db.clear()
    client.close()
    
@pytest.fixture
def created_user(
    client: TestClient
) -> dict:
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 180.5,
        "phone_number": "010-1234-1234"
    }
    
    res = client.post("/api/users", json=req)
    assert res.status_code == 201
    
    return res.json()

@pytest.fixture
def token(
    client: TestClient,
    created_user: dict
) -> dict:
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/token", json=req)
    
    assert res.status_code == 200
    return res.json()

@pytest.fixture
def created_session(
    client: TestClient,
    created_user: dict
) -> str:
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/session", json=req)
    assert res.status_code == 200
    assert "sid" in client.cookies
    
    return res.cookies["sid"]
