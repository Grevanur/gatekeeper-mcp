from fastapi.testclient import TestClient

from app.main import app


def test_health_endpoint_reports_a_connected_database() -> None:
    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "MCP Zero-Trust Gateway",
        "environment": "development",
        "database": "connected",
    }
