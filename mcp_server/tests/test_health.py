"""Tests for the Prowler MCP Server health endpoint."""

from starlette.testclient import TestClient

from prowler_mcp_server import __version__
from prowler_mcp_server.server import app


def test_health_returns_ietf_pass_response():
    """GET /health returns 200 with the IETF health-check body and headers."""
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/health+json"
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "status": "pass",
        "version": "1",
        "releaseId": __version__,
        "serviceId": "prowler-mcp-server",
        "description": "Prowler MCP Server",
    }


def test_health_release_id_matches_package_version():
    """The endpoint must surface the current package __version__ as releaseId.

    Drift between the response and the installed package would mislead any
    monitoring tool that uses releaseId to identify the running build.
    """
    client = TestClient(app)

    response = client.get("/health")

    assert response.json()["releaseId"] == __version__


def test_health_rejects_non_get_methods():
    """The endpoint only exposes GET; other verbs return 405."""
    client = TestClient(app)

    response = client.post("/health")

    assert response.status_code == 405
