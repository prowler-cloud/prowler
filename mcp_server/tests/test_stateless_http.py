"""Tests that the HTTP app issues no streamable-HTTP sessions."""

import json

from starlette.testclient import TestClient

from prowler_mcp_server.server import app

PROTOCOL_VERSION = "2025-06-18"

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

NEGOTIATED_HEADERS = MCP_HEADERS | {"MCP-Protocol-Version": PROTOCOL_VERSION}

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "tests", "version": "1"},
    },
}

INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}


def jsonrpc_result(response):
    """Return the JSON-RPC result, unwrapping SSE framing when present."""
    if response.headers["content-type"].startswith("text/event-stream"):
        payloads = [
            json.loads(line.removeprefix("data:").strip())
            for line in response.text.splitlines()
            if line.startswith("data:")
        ]
        assert len(payloads) == 1, response.text
        message = payloads[0]
    else:
        message = response.json()

    assert "error" not in message, message
    return message["result"]


def handshake(client):
    """Run the initialize / initialized lifecycle and return the initialize response."""
    response = client.post("/mcp/", json=INITIALIZE, headers=MCP_HEADERS)
    client.post("/mcp/", json=INITIALIZED, headers=NEGOTIATED_HEADERS)
    return response


def test_initialize_issues_no_session_id():
    """A stateful server issues mcp-session-id and then retains that session for
    the process lifetime, since most clients never send DELETE /mcp.
    """
    with TestClient(app) as client:
        response = client.post("/mcp/", json=INITIALIZE, headers=MCP_HEADERS)

        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers
        assert jsonrpc_result(response)["protocolVersion"] == PROTOCOL_VERSION


def test_tools_list_works_without_a_session():
    """Without this, any replica behind a load balancer needs session affinity."""
    with TestClient(app) as client:
        handshake(client)

        response = client.post(
            "/mcp/",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=NEGOTIATED_HEADERS,
        )

        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers
        assert len(jsonrpc_result(response)["tools"]) > 0
