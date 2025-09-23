from time import sleep

import pytest

from fastapi.testclient import TestClient


# auth/token
def test_create_token(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    
    res = client.post("/api/auth/token", json=req)
    res_json = res.json()
    
    assert res.status_code == 200
    assert res_json["access_token"] is not None
    assert res_json["refresh_token"] is not None
    
def test_create_token_invalid_password(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password123"
    }
    
    res = client.post("/api/auth/token", json=req)
    res_json = res.json()
    
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_010"
    assert res_json["error_msg"] == "INVALID ACCOUNT"
    
def test_create_token_invalid_email(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "spring@wafflestudio.com",
        "password": "password000"
    }
    
    res = client.post("/api/auth/token", json=req)
    res_json = res.json()
    
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_010"
    assert res_json["error_msg"] == "INVALID ACCOUNT"
    
def test_create_token_missing_email(
    client: TestClient,
    created_user: dict
):
    req = {
        "password": "password000"
    }
    
    res = client.post("/api/auth/token", json=req)
    res_json = res.json()
    
    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_001"
    assert res_json["error_msg"] == "MISSING VALUE"

def test_create_token_missing_password(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "fastapi@wafflestudio.com"
    }
    
    res = client.post("/api/auth/token", json=req)
    res_json = res.json()
    
    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_001"
    assert res_json["error_msg"] == "MISSING VALUE"
    
def test_refresh_token(
    client: TestClient,
    token: dict
):
    auth_header = {"Authorization": f"Bearer {token['refresh_token']}"}
    res = client.post("/api/auth/token/refresh", headers=auth_header)
    res_json = res.json()
    
    assert res.status_code == 200
    assert res_json["access_token"] is not None
    assert res_json["refresh_token"] is not None
    
def test_refresh_token_invalid_header(
    client: TestClient,
    token: dict
):
    auth_header = {"Authorization": f"{token['refresh_token']}"}
    res = client.post("/api/auth/token/refresh", headers=auth_header)
    res_json = res.json()
    
    assert res.status_code == 400
    assert res_json["error_code"] == "ERR_007"
    assert res_json["error_msg"] == "BAD AUTHORIZATION HEADER"

def test_refresh_token_expired(
    client: TestClient,
    created_user: dict,
    monkeypatch
):
    
    monkeypatch.setattr("src.auth.router.LONG_SESSION_LIFESPAN", 0)
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/token", json=req)
    token_json = res.json()
    
    sleep(1)
    auth_header = {'Authorization': f"Bearer {token_json['refresh_token']}"}
    res = client.post("/api/auth/token/refresh", headers=auth_header)
    res_json = res.json()
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_008"
    assert res_json["error_msg"] == "INVALID TOKEN"

def test_refresh_token_twice(
    client: TestClient,
    token: dict
):
    auth_header = {"Authorization": f"Bearer {token['refresh_token']}"}
    client.post("/api/auth/token/refresh", headers=auth_header)
    res = client.post("/api/auth/token/refresh", headers=auth_header)
    res_json = res.json()
    
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_008"
    assert res_json["error_msg"] == "INVALID TOKEN"
    
def test_refresh_token_invalid_token(
    client: TestClient,
    token: dict
):
    auth_header = {"Authorization": f"Bearer invalidtoken"}
    res = client.post("/api/auth/token/refresh", headers=auth_header)
    res_json = res.json()
    
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_008"
    assert res_json["error_msg"] == "INVALID TOKEN"
    
def test_refresh_token_without_header(
    client: TestClient,
    token: dict
):
    res = client.post("/api/auth/token/refresh")
    res_json = res.json()
    
    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_009"
    assert res_json["error_msg"] == "UNAUTHENTICATED"
    
def test_delete_token(
    client: TestClient,
    token: dict
):
    header = {'Authorization': f"Bearer {token['refresh_token']}"}
    res = client.delete("/api/auth/token", headers=header)
    assert res.status_code == 204

    res = client.post("/api/auth/token/refresh", headers=header)
    res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_008"
    assert res_json["error_msg"] == "INVALID TOKEN"

# auth/session
def test_session(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/session", json=req)
    sid_cookie_value = res.cookies["sid"]

    assert res.status_code == 200
    assert sid_cookie_value is not None

def test_session_invalid_email(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "spring@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/session", json=req)
    res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_010"
    assert res_json["error_msg"] == "INVALID ACCOUNT"

def test_session_invalid_password(
    client: TestClient,
    created_user: dict
):
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "invalid123"
    }
    res = client.post("/api/auth/session", json=req)
    res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_010"
    assert res_json["error_msg"] == "INVALID ACCOUNT"

def test_session_logout(
    client: TestClient,
    created_session: str
):
    res = client.delete("/api/auth/session")

    assert res.status_code == 204

    res = client.get("/api/users/me")
    res_json = res.json()
    
    assert "sid" not in client.cookies

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_009"
    assert res_json["error_msg"] == "UNAUTHENTICATED"

