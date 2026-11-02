"""Tests for the health check and root endpoints."""

from fastapi.testclient import TestClient
from backend import __version__


def test_root_endpoint(client: TestClient) -> None:
    """Ensure root endpoint returns service metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "AGENTGUARD-TEST"
    assert data["version"] == __version__
    assert "docs_url" in data
    assert "health_url" in data


def test_root_health_check(client: TestClient) -> None:
    """Ensure root /health probe returns 200 OK and expected schema fields."""
    response = client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "AGENTGUARD-TEST"
    assert data["version"] == __version__
    assert data["environment"] == "testing"
    assert data["database"] == "connected"
    assert "timestamp" in data
    assert "details" in data


def test_api_v1_health_check(client: TestClient) -> None:
    """Ensure versioned /api/v1/health returns identical healthy response."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["app_name"] == "AGENTGUARD-TEST"
    assert data["version"] == __version__
    assert data["database"] == "connected"

