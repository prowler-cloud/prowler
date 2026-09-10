"""Shared fixtures for the Prowler MCP Server test suite.

This module deliberately does not import ``prowler_mcp_server.server`` at module
scope. That import builds every tool and reads the environment, so it must happen
only once the environment is settled. Environment pinning itself lives in
``[tool.pytest_env]`` in ``pyproject.toml``, which is applied before any conftest
or test module is imported; the fixtures here only keep it pinned per test.

Three properties of the runtime shape everything below and are easy to get wrong:

1. ``prowler_app/server.py`` builds every tool at import time. A tool whose
   construction raises -- which is what happens with no API key -- is swallowed by
   ``load_all_tools``, leaving the ``prowler_*`` namespace silently empty. So the
   suite pins a fake key rather than stripping the real one.
2. ``BaseTool.__init__`` captured the ``ProwlerAPIClient`` singleton by reference
   at import time. Evicting it from the registry does not re-point the tools, so
   the client must be patched in place.
3. ``ProwlerAppAuth`` resolves ``PROWLER_MCP_TRANSPORT_MODE`` and ``API_BASE_URL``
   in its default arguments, which are evaluated once at module import.
   ``monkeypatch.setenv`` cannot change them -- pass ``mode=``/``base_url=``
   explicitly instead.
"""

import socket
from collections.abc import Callable, Iterator

import httpx
import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from tests.helpers.http import MockRouter
from tests.helpers.tokens import FAKE_API_KEY

# Must match [tool.pytest_env] in pyproject.toml: the env var is what the code
# reads at import time, this constant is what tests assert against.
TEST_API_BASE_URL = "https://api.testing.invalid/api/v1"


# --------------------------------------------------------------- environment


@pytest.fixture(autouse=True)
def _pinned_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the runtime environment to deterministic test values.

    Pinned rather than stripped: a missing ``PROWLER_API_KEY`` collapses the
    ``prowler_*`` namespace to zero tools instead of failing loudly.
    ``PROWLER_APP_API_KEY`` is the deprecated fallback and is removed so only a
    test that sets it exercises that path.

    This also stops a developer's gitignored ``mcp_server/.env`` or shell
    environment from reaching the suite.
    """
    monkeypatch.setenv("PROWLER_API_KEY", FAKE_API_KEY)
    monkeypatch.setenv("API_BASE_URL", TEST_API_BASE_URL)
    monkeypatch.setenv("PROWLER_MCP_TRANSPORT_MODE", "stdio")
    monkeypatch.delenv("PROWLER_APP_API_KEY", raising=False)


@pytest.fixture(autouse=True)
def _no_real_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail loudly on any real outbound socket connection.

    The subject under test is an HTTP client, so a route that was not mocked must
    fail fast and obviously rather than quietly reaching hub.prowler.com and
    making the suite slow, flaky and dependent on someone else's uptime.

    In-process transports (Starlette's ``TestClient``, fastmcp's in-memory
    client) do not open sockets, so this does not interfere with them.
    """

    def _blocked(self: socket.socket, address: object, *_: object) -> None:
        raise RuntimeError(
            f"Blocked a real network connection to {address}. Drive HTTP through "
            "the mock_api_client, hub_router or docs_router fixtures."
        )

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)


# ----------------------------------------------------------------- API client


@pytest.fixture(autouse=True)
def _singleton_registry_guard() -> Iterator[None]:
    """Snapshot and restore the singleton registry around every test.

    Deliberately a snapshot, not a clear. ``BaseTool.__init__`` captured the
    ``ProwlerAPIClient`` instance by reference at import time, so evicting it
    would leave every registered tool pointing at an orphan that later fixtures
    cannot patch -- one holding a real ``httpx.AsyncClient``. Restoring keeps a
    test that resets on purpose from leaking into the next one.
    """
    from prowler_mcp_server.prowler_app.utils.api_client import SingletonMeta

    snapshot = dict(SingletonMeta._instances)
    try:
        yield
    finally:
        SingletonMeta._instances.clear()
        SingletonMeta._instances.update(snapshot)


@pytest.fixture
def mock_router() -> MockRouter:
    """An empty route registry and request recorder for this test."""
    return MockRouter()


@pytest.fixture
def api_client():
    """The live ``ProwlerAPIClient`` singleton that every registered tool holds."""
    from prowler_mcp_server.prowler_app.utils.api_client import ProwlerAPIClient

    return ProwlerAPIClient()


@pytest.fixture
def mock_api_client(api_client, mock_router: MockRouter) -> Iterator:
    """The API client singleton, with its transport driven by ``mock_router``.

    Swaps ``.client`` in place rather than constructing a fresh client, so tools
    reached through the MCP protocol -- which hold this exact instance -- are
    mocked too. Everything else still runs for real: URL joining, query encoding,
    auth headers, ``raise_for_status()`` and the JSON:API error unwrapping.
    """
    original = api_client.client
    api_client.client = httpx.AsyncClient(transport=mock_router.transport, timeout=30.0)
    try:
        yield api_client
    finally:
        api_client.client = original


@pytest.fixture
def isolated_api_client() -> Iterator[type]:
    """Evict the singleton so a test can exercise construction semantics.

    Only for tests *about* ``ProwlerAPIClient`` itself -- its ``__init__`` or its
    singleton identity. Anything reached through a tool must use
    ``mock_api_client``, because the tools still point at the original instance.
    """
    from prowler_mcp_server.prowler_app.utils.api_client import (
        ProwlerAPIClient,
        SingletonMeta,
    )

    SingletonMeta._instances.pop(ProwlerAPIClient, None)
    yield ProwlerAPIClient


# --------------------------------------------------------------- MCP surface


@pytest.fixture(scope="session")
def mcp_root_server():
    """The mounted root MCP server, imported lazily because importing has effects.

    Tests open their own client over this (``async with Client(mcp_root_server)``)
    rather than receiving a connected one, because FastMCP warns that holding a
    client in a fixture causes hard-to-diagnose event-loop problems.
    """
    from prowler_mcp_server.server import prowler_mcp_server

    return prowler_mcp_server


@pytest.fixture
def health_client() -> Iterator[TestClient]:
    """An ASGI client over the stateless HTTP app, for the ``/health`` route."""
    from prowler_mcp_server.server import app

    with TestClient(app) as client:
        yield client


@pytest.fixture
def http_request_headers() -> Iterator[Callable[..., None]]:
    """Return a callable that makes ``get_http_headers()`` observe given headers.

    In HTTP transport mode ``ProwlerAppAuth`` reads the authorization header
    through fastmcp's request context variable. Setting that variable directly is
    what lets an auth test run without standing up a real HTTP server.

    Underscores in keyword names become hyphens, so ``x_request_id=`` sets
    ``x-request-id``.
    """
    from fastmcp.server.http import _current_http_request

    def _set(**headers: str) -> None:
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/mcp",
            "raw_path": b"/mcp",
            "root_path": "",
            "scheme": "http",
            "query_string": b"",
            "server": ("testserver", 80),
            "client": ("testclient", 50000),
            "headers": [
                (name.lower().replace("_", "-").encode(), value.encode())
                for name, value in headers.items()
            ],
        }
        _current_http_request.set(Request(scope))

    try:
        yield _set
    finally:
        # Not a token-based reset: an async test calls `_set` inside its task,
        # and asyncio gives each task its own copy of the context, so the token
        # cannot be reset from here and the task's value is discarded with the
        # task anyway. Clearing the value covers the sync-test case, where the
        # set would otherwise persist into the next test.
        _current_http_request.set(None)


# ------------------------------------------------------- hub / docs sub-servers


def _clone_with_transport(
    client: httpx.Client, transport: httpx.MockTransport
) -> httpx.Client:
    """Copy a sync client's base URL and headers onto a mock transport."""
    return httpx.Client(
        base_url=client.base_url,
        headers=dict(client.headers),
        transport=transport,
    )


@pytest.fixture
def hub_router(monkeypatch: pytest.MonkeyPatch, mock_router: MockRouter) -> MockRouter:
    """Route the Prowler Hub sub-server's two module-level sync clients.

    Hub tools are synchronous and reach for these clients by module global, so
    they are replaced on the module rather than injected.
    """
    from prowler_mcp_server.prowler_hub import server as hub

    for name in ("prowler_hub_client", "github_raw_client"):
        monkeypatch.setattr(
            hub, name, _clone_with_transport(getattr(hub, name), mock_router.transport)
        )
    return mock_router


@pytest.fixture
def docs_router(monkeypatch: pytest.MonkeyPatch, mock_router: MockRouter) -> MockRouter:
    """Route the documentation search engine's two sync clients."""
    from prowler_mcp_server.prowler_documentation import server as docs

    engine = docs.prowler_docs_search_engine
    for name in ("mintlify_client", "docs_client"):
        monkeypatch.setattr(
            engine,
            name,
            _clone_with_transport(getattr(engine, name), mock_router.transport),
        )
    return mock_router
