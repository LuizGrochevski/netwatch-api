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

def test_register_success():
    res = client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    assert res.status_code == 201
    assert res.json()["message"] == "Usuário criado com sucesso"

def test_register_duplicate():
    client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    res = client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    assert res.status_code == 400
    assert res.json()["detail"] == "Usuário já existe"

def test_login_success():
    client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    res = client.post("/auth/login", data={"username": "testuser", "password": "senha123"})
    assert res.status_code == 200
    assert "access_token" in res.json()
    assert res.json()["token_type"] == "bearer"

def test_login_wrong_password():
    client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    res = client.post("/auth/login", data={"username": "testuser", "password": "errada"})
    assert res.status_code == 401

def test_login_unknown_user():
    res = client.post("/auth/login", data={"username": "naoexiste", "password": "senha123"})
    assert res.status_code == 401

def test_get_me():
    client.post("/auth/register", json={"username": "testuser", "password": "senha123"})
    login = client.post("/auth/login", data={"username": "testuser", "password": "senha123"})
    token = login.json()["access_token"]
    res = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    assert res.json()["username"] == "testuser"

def test_get_me_unauthorized():
    res = client.get("/me")
    assert res.status_code == 401
