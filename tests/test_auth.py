from fastapi.testclient import TestClient
from src.app import app

client = TestClient(app)


def test_register_and_login():
    email = "ci_test_user@example.com"
    password = "supersecret"

    # Register
    r = client.post("/auth/register", json={"email": email, "password": password, "full_name": "CI Test"})
    assert r.status_code == 200
    assert r.json().get("email") == email

    # Login
    r2 = client.post("/auth/login", json={"email": email, "password": password})
    assert r2.status_code == 200
    data = r2.json()
    assert "access_token" in data
