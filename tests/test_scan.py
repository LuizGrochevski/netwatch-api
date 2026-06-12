import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db, get_connection

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_db():
    init_db()
    conn = get_connection()
    conn.execute("DELETE FROM users")
    conn.execute("DELETE FROM scans")
    conn.commit()
    conn.close()

@pytest.fixture
def auth_token():
    client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    res = client.post("/auth/login", data={"username": "testuser", "password": "senha123"})
    return res.json()["access_token"]

def test_scan_unauthorized():
    res = client.post("/scan", json={"targets": ["google.com"]})
    assert res.status_code == 401

def test_scan_success(auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["localhost"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 202
    data = res.json()
    assert "id" in data
    assert "results" in data
    assert data["status"] == "completed"

def test_scan_result_structure(auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["localhost"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    result = res.json()["results"][0]
    assert "target" in result
    assert "open_ports" in result
    assert "hostname" in result
    assert isinstance(result["open_ports"], list)

def test_get_scan_by_id(auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["localhost"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    res = client.get(f"/scan/{scan_id}", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert res.json()["id"] == scan_id

def test_get_scan_not_found(auth_token):
    res = client.get("/scan/9999", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 404

def test_history(auth_token):
    client.post("/scan", json={"targets": ["localhost"]}, headers={"Authorization": f"Bearer {auth_token}"})
    client.post("/scan", json={"targets": ["localhost"]}, headers={"Authorization": f"Bearer {auth_token}"})
    res = client.get("/history", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert len(res.json()) == 2
