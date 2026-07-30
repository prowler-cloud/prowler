"""Tests that the HTTP app issues no streamable-HTTP sessions."""

from starlette.testclient import TestClient

from prowler_mcp_server.server import app

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

INITIALIZE = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "tests", "version": "1"},
    },
}


def test_initialize_issues_no_session_id():
    """A stateful server returns mcp-session-id and then retains that session
    until the client sends DELETE /mcp. Most clients never do, so each session
    is held for the process lifetime and the server leaks memory in proportion
    to traffic. Asserting the header is absent keeps the app stateless.
    """
    with TestClient(app) as client:
        response = client.post("/mcp/", json=INITIALIZE, headers=MCP_HEADERS)

        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers


def test_tools_list_works_without_a_session():
    """Stateless mode must serve requests that carry no session, otherwise any
    replica behind a load balancer would need session affinity to work.
    """
    with TestClient(app) as client:
        client.post("/mcp/", json=INITIALIZE, headers=MCP_HEADERS)

        response = client.post(
            "/mcp/",
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            headers=MCP_HEADERS,
        )

        assert response.status_code == 200
        assert "mcp-session-id" not in response.headers
        assert '"tools"' in response.text
