"""Tests for Prowler API authentication.

Reference for later branches: ``ProwlerAppAuth`` resolves its ``mode`` and
``base_url`` in default arguments, which Python evaluates once at module import.
``monkeypatch.setenv`` therefore has no effect on them -- always pass ``mode=``
and ``base_url=`` explicitly, as these tests do.
"""

import pytest

from prowler_mcp_server.prowler_app.utils.auth import ProwlerAppAuth
from tests.helpers.tokens import FAKE_API_KEY, MALFORMED_API_KEY, fake_jwt


async def test_stdio_mode_reads_the_api_key_from_the_environment():
    """In STDIO transport the key comes from the process environment."""
    auth = ProwlerAppAuth(mode="stdio")

    assert await auth.get_valid_token() == FAKE_API_KEY


def test_stdio_mode_rejects_a_key_without_the_prowler_prefix(
    monkeypatch: pytest.MonkeyPatch,
):
    """A key that is not `pk_`-prefixed is refused at construction.

    Failing here rather than on the first API call is what turns a
    misconfiguration into an immediate, readable startup error.
    """
    monkeypatch.setenv("PROWLER_API_KEY", MALFORMED_API_KEY)

    with pytest.raises(ValueError, match="Prowler API key format is incorrect"):
        ProwlerAppAuth(mode="stdio")


async def test_http_mode_accepts_a_bearer_api_key(http_request_headers):
    """In HTTP transport the token comes from the request's Authorization header."""
    http_request_headers(authorization=f"Bearer {FAKE_API_KEY}")

    auth = ProwlerAppAuth(mode="http")

    assert await auth.get_valid_token() == FAKE_API_KEY


async def test_http_mode_rejects_an_expired_jwt(http_request_headers):
    """An expired JWT is refused locally instead of being forwarded to the API."""
    http_request_headers(authorization=f"Bearer {fake_jwt(expires_in=-60)}")

    auth = ProwlerAppAuth(mode="http")

    with pytest.raises(ValueError, match="Token has expired"):
        await auth.get_valid_token()


def test_api_keys_and_jwts_use_different_authorization_schemes():
    """Prowler API keys authenticate with `Api-Key`, JWTs with `Bearer`."""
    auth = ProwlerAppAuth(mode="stdio")

    assert auth.get_headers(FAKE_API_KEY)["Authorization"] == f"Api-Key {FAKE_API_KEY}"

    jwt = fake_jwt()
    assert auth.get_headers(jwt)["Authorization"] == f"Bearer {jwt}"
