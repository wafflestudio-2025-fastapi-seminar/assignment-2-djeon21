import pytest
import httpx
from fastapi.testclient import TestClient

from server_ip import server_ip

def test_deployment(
    client: TestClient
):
    assert server_ip != "127.0.0.1"
    assert server_ip != "localhost"
    assert server_ip != "0.0.0.0"
    
    local_res = client.get("/health")
    local_res_json = local_res.json()

    assert local_res_json.get("status") == "ok"


    remote_res = httpx.get(f"http://{server_ip}/health")
    remote_res_json = remote_res.json()

    assert remote_res_json.get("status") == "ok"
    
    assert local_res_json.get("hash") == remote_res_json.get("hash")


    