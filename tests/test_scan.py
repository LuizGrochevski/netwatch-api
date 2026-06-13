import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch
from app.main import app
from app.database import init_db, get_connection

client = TestClient(app)

MOCK_SCAN_RESULT = [
    {
        "target": "192.168.0.1",
        "engine": "sentinel-rs",
        "protocol": "tcp",
        "ports_scanned": "80,443,22",
        "open_ports": [
            {"port": 80, "service": "HTTP", "status": "Aberta (TCP)"},
            {"port": 443, "service": "HTTPS", "status": "Aberta (TCP)"}
        ],
        "error": None
    }
]

MOCK_UNREACHABLE_RESULT = [
    {
        "target": "10.0.0.99",
        "engine": "sentinel-rs",
        "protocol": "tcp",
        "ports_scanned": "80,443",
        "open_ports": [],
        "error": "Host unreachable or no ports found"
    }
]

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
    res = client.post("/scan", json={"targets": ["192.168.0.1"]})
    assert res.status_code == 401

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_scan_success(mock_sentinel, auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"], "ports": "80,443,22", "protocol": "tcp"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 202
    data = res.json()
    assert data["status"] == "completed"
    assert "id" in data
    mock_sentinel.assert_called_once_with(["192.168.0.1"], "80,443,22", "tcp")

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_scan_result_structure(mock_sentinel, auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    result = res.json()["results"][0]
    assert "target" in result
    assert "open_ports" in result
    assert "engine" in result
    assert result["engine"] == "sentinel-rs"
    assert isinstance(result["open_ports"], list)

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_scan_open_ports(mock_sentinel, auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"], "ports": "80,443,22"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    ports = res.json()["results"][0]["open_ports"]
    assert len(ports) == 2
    assert ports[0]["port"] == 80
    assert ports[0]["service"] == "HTTP"

@patch("app.routes.run_sentinel", return_value=MOCK_UNREACHABLE_RESULT)
def test_scan_unreachable_host(mock_sentinel, auth_token):
    res = client.post(
        "/scan",
        json={"targets": ["10.0.0.99"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 202
    result = res.json()["results"][0]
    assert result["open_ports"] == []
    assert result["error"] == "Host unreachable or no ports found"

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_get_scan_by_id(mock_sentinel, auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    res = client.get(f"/scan/{scan_id}", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert res.json()["id"] == scan_id

def test_get_scan_not_found(auth_token):
    res = client.get("/scan/9999", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 404

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_report_csv(mock_sentinel, auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    res = client.get(f"/scan/{scan_id}/report?format=csv", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "192.168.0.1" in res.text
    assert "HTTP" in res.text

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_report_markdown(mock_sentinel, auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    res = client.get(f"/scan/{scan_id}/report?format=markdown", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert "192.168.0.1" in res.text
    assert "HTTP" in res.text

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_history(mock_sentinel, auth_token):
    client.post("/scan", json={"targets": ["192.168.0.1"]}, headers={"Authorization": f"Bearer {auth_token}"})
    client.post("/scan", json={"targets": ["192.168.0.1"]}, headers={"Authorization": f"Bearer {auth_token}"})
    res = client.get("/history", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert len(res.json()["data"]) == 2

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_delete_scan(mock_sentinel, auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    res = client.delete(f"/scan/{scan_id}", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    assert "deletado" in res.json()["message"]

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_delete_scan_not_found(mock_sentinel, auth_token):
    res = client.delete("/scan/9999", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 404

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_delete_scan_removes_from_history(mock_sentinel, auth_token):
    post = client.post(
        "/scan",
        json={"targets": ["192.168.0.1"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    scan_id = post.json()["id"]
    client.delete(f"/scan/{scan_id}", headers={"Authorization": f"Bearer {auth_token}"})
    res = client.get("/history", headers={"Authorization": f"Bearer {auth_token}"})
    ids = [s["id"] for s in res.json()["data"]]
    assert scan_id not in ids

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_history_paginacao(mock_sentinel, auth_token):
    for _ in range(5):
        client.post("/scan", json={"targets": ["192.168.0.1"]}, headers={"Authorization": f"Bearer {auth_token}"})
    res = client.get("/history?page=1&limit=3", headers={"Authorization": f"Bearer {auth_token}"})
    assert res.status_code == 200
    data = res.json()
    assert data["page"] == 1
    assert data["limit"] == 3
    assert data["total"] == 5
    assert data["pages"] == 2
    assert len(data["data"]) == 3

@patch("app.routes.run_sentinel", return_value=MOCK_SCAN_RESULT)
def test_history_pagina_2(mock_sentinel, auth_token):
    for _ in range(5):
        client.post("/scan", json={"targets": ["192.168.0.1"]}, headers={"Authorization": f"Bearer {auth_token}"})
    res = client.get("/history?page=2&limit=3", headers={"Authorization": f"Bearer {auth_token}"})
    data = res.json()
    assert data["page"] == 2
    assert len(data["data"]) == 2
