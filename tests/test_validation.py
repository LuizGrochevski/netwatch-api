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

# --- USERNAME ---

def test_username_muito_curto():
    res = client.post("/auth/register", json={"username": "ab", "password": "senha123"})
    assert res.status_code == 422

def test_username_muito_longo():
    res = client.post("/auth/register", json={"username": "a" * 33, "password": "senha123"})
    assert res.status_code == 422

def test_username_caractere_invalido():
    res = client.post("/auth/register", json={"username": "user@name", "password": "senha123"})
    assert res.status_code == 422

def test_username_valido():
    res = client.post("/auth/register", json={"username": "user_123", "password": "senha123"})
    assert res.status_code == 201

# --- PASSWORD ---

def test_password_muito_curta():
    res = client.post("/auth/register", json={"username": "testuser", "password": "123"})
    assert res.status_code == 422

def test_password_muito_longa():
    res = client.post("/auth/register", json={"username": "testuser", "password": "a" * 73})
    assert res.status_code == 422

# --- TARGETS ---

def test_targets_vazio(auth_token):
    res = client.post("/scan",
        json={"targets": []},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

def test_targets_invalido(auth_token):
    res = client.post("/scan",
        json={"targets": ["not a valid target!!"]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

def test_targets_limite_excedido(auth_token):
    res = client.post("/scan",
        json={"targets": [f"192.168.0.{i}" for i in range(11)]},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

# --- PORTS ---

def test_porta_invalida(auth_token):
    res = client.post("/scan",
        json={"targets": ["192.168.0.1"], "ports": "abc"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

def test_porta_fora_do_range(auth_token):
    res = client.post("/scan",
        json={"targets": ["192.168.0.1"], "ports": "99999"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

def test_porta_range_valido(auth_token):
    from unittest.mock import patch
    with patch("app.routes.run_sentinel", return_value=[]):
        res = client.post("/scan",
            json={"targets": ["192.168.0.1"], "ports": "80-90"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    assert res.status_code == 202

# --- PROTOCOL ---

def test_protocol_invalido(auth_token):
    res = client.post("/scan",
        json={"targets": ["192.168.0.1"], "protocol": "ftp"},
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    assert res.status_code == 422

def test_protocol_udp_valido(auth_token):
    from unittest.mock import patch
    with patch("app.routes.run_sentinel", return_value=[]):
        res = client.post("/scan",
            json={"targets": ["192.168.0.1"], "protocol": "udp"},
            headers={"Authorization": f"Bearer {auth_token}"}
        )
    assert res.status_code == 202
