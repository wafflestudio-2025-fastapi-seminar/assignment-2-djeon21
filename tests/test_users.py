import pytest
import json
from time import sleep
from freezegun import freeze_time
from datetime import timedelta

from fastapi.testclient import TestClient

def test_create_user_without_bio(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 180.5,
        "phone_number": "010-1234-1234"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 201
    assert isinstance(res_json["user_id"], int)
    assert res_json["name"] == req["name"]
    assert res_json["email"] == req["email"]
    assert res_json["height"] == req["height"]
    assert res_json["phone_number"] == req["phone_number"]

def test_create_user_with_bio(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 180.5,
        "phone_number": "010-1234-1234",
        "bio": "안녕하세요"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 201
    assert isinstance(res_json["user_id"], int)
    assert res_json["name"] == req["name"]
    assert res_json["email"] == req["email"]
    assert res_json["height"] == req["height"]
    assert res_json["phone_number"] == req["phone_number"]
    assert res_json["bio"] == req["bio"]


def test_create_user_without_content(
    client: TestClient
):
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 175.2,
        "phone_number": "010-1234-1234"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()
    
    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_001"
    assert res_json["error_msg"] == "MISSING VALUE"


def test_create_user_short_password(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "short",
        "height": 175.2,
        "phone_number": "010-1234-1234"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_002"
    assert res_json["error_msg"] == "INVALID PASSWORD"

def test_create_user_long_password(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "longpassword123456789",
        "height": 175.2,
        "phone_number": "010-1234-1234"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_002"
    assert res_json["error_msg"] == "INVALID PASSWORD" 

def test_create_user_invalid_phone_number(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 175.2,
        "phone_number": "01012341234"
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_003"
    assert res_json["error_msg"] == "INVALID PHONE NUMBER"

def test_create_user_long_bio(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 175.2,
        "phone_number": "010-1234-1234",
        "bio": "a" * 501
    }
    res = client.post("/api/users", json=req)
    res_json = res.json()

    assert res.status_code == 422
    assert res_json["error_code"] == "ERR_004"
    assert res_json["error_msg"] == "BIO TOO LONG"

def test_create_user_email_conflict(
    client: TestClient
):
    req = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "password": "password000",
        "height": 180.5,
        "phone_number": "010-1234-1234"
    }
    res = client.post("/api/users", json=req)
    res2 = client.post("/api/users", json=req)

    res2_json = res2.json()

    assert res2.status_code == 409
    assert res2_json["error_code"] == "ERR_005"
    assert res2_json["error_msg"] == "EMAIL ALREADY EXISTS"

def test_profile_with_token(
    client: TestClient,
    token: dict
):
    to_comp = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "height": 180.5,
        "phone_number": "010-1234-1234"
    }
    auth_header = {'Authorization': f"Bearer {token['access_token']}"}
    res = client.get("/api/users/me", headers=auth_header)
    res_json = res.json()
    
    assert res.status_code == 200
    assert res_json["name"] == to_comp["name"]
    assert res_json["email"] == to_comp["email"]
    assert res_json["height"] == to_comp["height"]
    assert res_json["phone_number"] == to_comp["phone_number"]
    
def test_profile_with_expired_token(
    client: TestClient,
    created_user: dict,
    monkeypatch
):
    monkeypatch.setattr("src.auth.router.SHORT_SESSION_LIFESPAN", 0)
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/token", json=req)
    token_json = res.json()
    
    sleep(1)
    auth_header = {'Authorization': f"Bearer {token_json['access_token']}"}
    res = client.get("/api/users/me", headers=auth_header)
    res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_008"
    assert res_json["error_msg"] == "INVALID TOKEN"

def test_profile_with_session(
    client: TestClient,
    created_user: dict,
    monkeypatch
):

    to_comp = {
        "name": "김와플",
        "email": "fastapi@wafflestudio.com",
        "height": 180.5,
        "phone_number": "010-1234-1234"
    }
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }
    res = client.post("/api/auth/session", json=req)
    assert "sid" in res.cookies
    session_id = res.cookies["sid"]

    client.cookies.set("sid", session_id)
    res = client.get("/api/users/me")
    res_json = res.json()

    assert res.status_code == 200
    assert res_json["name"] == to_comp["name"]
    assert res_json["email"] == to_comp["email"]
    assert res_json["height"] == to_comp["height"]
    assert res_json["phone_number"] == to_comp["phone_number"]

def test_profile_with_expired_session(
    client: TestClient,
    created_user: dict,
    monkeypatch
):
    monkeypatch.setattr("src.auth.router.LONG_SESSION_LIFESPAN", 1)
    future_time = timedelta(minutes=1, seconds=1)
    req = {
        "email": "fastapi@wafflestudio.com",
        "password": "password000"
    }

    res = client.post("/api/auth/session", json=req)
    session_id = res.cookies["sid"]
    
    with freeze_time() as frozen_time:
        frozen_time.tick(delta=future_time)
        client.cookies.set("sid", session_id)
        res = client.get("/api/users/me")
        res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_006"
    assert res_json["error_msg"] == "INVALID SESSION"
    
def test_profile_without_auth(
    client: TestClient,
    created_user: dict
):
    res = client.get("/api/users/me")
    res_json = res.json()

    assert res.status_code == 401
    assert res_json["error_code"] == "ERR_009"
    assert res_json["error_msg"] == "UNAUTHENTICATED"