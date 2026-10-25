from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_api_root_contract():
    response = client.get("/api")
    assert response.status_code == 200
    body = response.json()
    assert body["application"] == "FTTW"
    assert body["version"] == "1.4.0"


def test_openapi_available():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert "/api/device-candidates" in paths
    assert "/api/device-candidates/{candidate_id}/approve" in paths
    assert "/api/device-candidates/{candidate_id}/reject" in paths
    assert "/api/device-candidates/{candidate_id}/reopen" in paths
    assert "/api/device-candidates/{candidate_id}/register" in paths
    assert "/api/device-candidates/{candidate_id}/audit" in paths
    assert "/api/device-candidates/summary" in paths
    assert "/api/devices/operational-summary" in paths
    assert "/api/devices/{device_id}/placement" in paths


def test_docs_available():
    response = client.get("/docs")
    assert response.status_code == 200
    assert "Swagger UI" in response.text
