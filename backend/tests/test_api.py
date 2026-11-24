from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_check_scam():
    r = client.post("/api/check", json={
        "text": "Dear consumer, your electricity will be disconnected tonight because "
                "last month bill was not updated. Call officer 9876543210 immediately.",
        "language": "en",
    })
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "scam"
    assert "9876543210" not in body["masked_text"]


def test_rejects_empty_and_bad_language():
    assert client.post("/api/check", json={"text": ""}).status_code == 422
    assert client.post("/api/check", json={"text": "hi", "language": "fr"}).status_code == 422
