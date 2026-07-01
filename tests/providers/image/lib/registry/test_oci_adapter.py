import base64
import socket
from unittest.mock import MagicMock, patch

import pytest
import requests

from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryAuthError,
    ImageRegistryCatalogError,
    ImageRegistryNetworkError,
)
from prowler.providers.image.lib.registry.oci_adapter import OciRegistryAdapter


def _fake_getaddrinfo(host_to_ip: dict):
    """Build a getaddrinfo stub that resolves names from host_to_ip."""

    def _stub(host, *_args, **_kwargs):
        if host not in host_to_ip:
            raise socket.gaierror(f"unresolved host: {host}")
        ip = host_to_ip[host]
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        return [(family, socket.SOCK_STREAM, 0, "", (ip, 0))]

    return _stub


@pytest.fixture(autouse=True)
def _default_dns_resolves_public(monkeypatch):
    """Make every host resolve to a public IP by default.

    Individual tests may override with their own patch on
    ``prowler.providers.image.lib.registry.base.socket.getaddrinfo``.
    """

    def _stub(_host, *_a, **_kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0))]

    monkeypatch.setattr(
        "prowler.providers.image.lib.registry.base.socket.getaddrinfo", _stub
    )


class TestOciAdapterInit:
    def test_normalise_url_adds_https(self):
        adapter = OciRegistryAdapter("myregistry.io")
        assert adapter._base_url == "https://myregistry.io"

    def test_normalise_url_keeps_http(self):
        adapter = OciRegistryAdapter("http://myregistry.io")
        assert adapter._base_url == "http://myregistry.io"

    def test_normalise_url_strips_trailing_slash(self):
        adapter = OciRegistryAdapter("https://myregistry.io/")
        assert adapter._base_url == "https://myregistry.io"

    def test_stores_credentials(self):
        adapter = OciRegistryAdapter(
            "reg.io", username="u", password="p", token="t", verify_ssl=False
        )
        assert adapter.username == "u"
        assert adapter.password == "p"
        assert adapter.token == "t"
        assert adapter.verify_ssl is False


class TestOciAdapterAuth:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_with_token(self, mock_request):
        adapter = OciRegistryAdapter("reg.io", token="my-token")
        adapter._ensure_auth()
        assert adapter._bearer_token == "my-token"
        mock_request.assert_not_called()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_anonymous_ok(self, mock_request):
        resp = MagicMock(status_code=200)
        mock_request.return_value = resp
        adapter = OciRegistryAdapter("reg.io")
        adapter._ensure_auth()
        assert adapter._bearer_token is None

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_bearer_challenge(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={
                "Www-Authenticate": 'Bearer realm="https://auth.reg.io/token",service="registry"'
            },
        )
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "bearer-tok"}
        mock_request.side_effect = [ping_resp, token_resp]
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        adapter._ensure_auth()
        assert adapter._bearer_token == "bearer-tok"

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_403_raises(self, mock_request):
        resp = MagicMock(status_code=403)
        mock_request.return_value = resp
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryAuthError):
            adapter._ensure_auth()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_basic_challenge_with_creds(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={"Www-Authenticate": 'Basic realm="https://ecr.aws"'},
        )
        mock_request.return_value = ping_resp
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password="tok")
        adapter._ensure_auth()
        assert adapter._basic_auth_verified is True
        assert adapter._bearer_token is None

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_ensure_auth_basic_challenge_no_creds(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={"Www-Authenticate": 'Basic realm="https://ecr.aws"'},
        )
        mock_request.return_value = ping_resp
        adapter = OciRegistryAdapter("ecr.aws")
        with pytest.raises(ImageRegistryAuthError):
            adapter._ensure_auth()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_basic_auth_used_in_requests(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={"Www-Authenticate": 'Basic realm="https://ecr.aws"'},
        )
        catalog_resp = MagicMock(status_code=200, headers={})
        catalog_resp.json.return_value = {"repositories": ["myapp"]}
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password="tok")
        adapter._ensure_auth()
        adapter._authed_request("GET", "https://ecr.aws/v2/_catalog")
        # The catalog request should use Basic auth (auth kwarg), not Bearer header
        call_kwargs = mock_request.call_args_list[1][1]
        assert call_kwargs.get("auth") == ("AWS", "tok")
        assert "Authorization" not in call_kwargs.get("headers", {})

    def test_resolve_basic_credentials_decodes_base64_token(self):
        raw_password = "real-jwt-password"
        encoded = base64.b64encode(f"AWS:{raw_password}".encode()).decode()
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password=encoded)
        user, pwd = adapter._resolve_basic_credentials()
        assert user == "AWS"
        assert pwd == raw_password

    def test_resolve_basic_credentials_passthrough_raw_password(self):
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password="plain-pass")
        user, pwd = adapter._resolve_basic_credentials()
        assert user == "AWS"
        assert pwd == "plain-pass"

    def test_resolve_basic_credentials_passthrough_invalid_base64(self):
        adapter = OciRegistryAdapter(
            "ecr.aws", username="AWS", password="not!valid~base64"
        )
        user, pwd = adapter._resolve_basic_credentials()
        assert user == "AWS"
        assert pwd == "not!valid~base64"

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_basic_auth_decodes_ecr_token_in_request(self, mock_request):
        raw_password = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.abc"
        encoded = base64.b64encode(f"AWS:{raw_password}".encode()).decode()
        ping_resp = MagicMock(
            status_code=401,
            headers={"Www-Authenticate": 'Basic realm="https://ecr.aws"'},
        )
        catalog_resp = MagicMock(status_code=200, headers={})
        catalog_resp.json.return_value = {"repositories": ["myapp"]}
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password=encoded)
        adapter._ensure_auth()
        adapter._authed_request("GET", "https://ecr.aws/v2/_catalog")
        call_kwargs = mock_request.call_args_list[1][1]
        assert call_kwargs.get("auth") == ("AWS", raw_password)

    def test_resolve_basic_credentials_none_password(self):
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password=None)
        user, pwd = adapter._resolve_basic_credentials()
        assert user == "AWS"
        assert pwd is None

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_authed_request_retries_on_401_with_bearer(self, mock_request):
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        adapter._bearer_token = "expired-token"
        # First request: 401 (expired token)
        resp_401 = MagicMock(status_code=401)
        # _ensure_auth ping: 401 with bearer challenge
        ping_resp = MagicMock(
            status_code=401,
            headers={
                "Www-Authenticate": 'Bearer realm="https://auth.reg.io/token",service="registry"'
            },
        )
        # Token exchange: success
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "new-token"}
        # Second request: 200 (new token works)
        resp_200 = MagicMock(status_code=200)
        mock_request.side_effect = [resp_401, ping_resp, token_resp, resp_200]
        result = adapter._authed_request("GET", "https://reg.io/v2/myapp/tags/list")
        assert result.status_code == 200
        assert adapter._bearer_token == "new-token"
        assert mock_request.call_count == 4

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_authed_request_no_retry_on_401_without_bearer(self, mock_request):
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        adapter._basic_auth_verified = True
        # No bearer token — using basic auth
        resp_401 = MagicMock(status_code=401)
        mock_request.return_value = resp_401
        result = adapter._authed_request("GET", "https://reg.io/v2/_catalog")
        assert result.status_code == 401
        # Should only be called once (no retry for basic auth)
        assert mock_request.call_count == 1


class TestOciAdapterListRepositories:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_repos_single_page(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        catalog_resp = MagicMock(status_code=200, headers={})
        catalog_resp.json.return_value = {
            "repositories": ["app/frontend", "app/backend"]
        }
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("reg.io")
        repos = adapter.list_repositories()
        assert repos == ["app/frontend", "app/backend"]

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_repos_paginated(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        page1_resp = MagicMock(
            status_code=200,
            headers={"Link": '<https://reg.io/v2/_catalog?n=200&last=b>; rel="next"'},
        )
        page1_resp.json.return_value = {"repositories": ["a"]}
        page2_resp = MagicMock(status_code=200, headers={})
        page2_resp.json.return_value = {"repositories": ["b"]}
        mock_request.side_effect = [ping_resp, page1_resp, page2_resp]
        adapter = OciRegistryAdapter("reg.io")
        repos = adapter.list_repositories()
        assert repos == ["a", "b"]

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_repos_404_raises(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        catalog_resp = MagicMock(status_code=404)
        mock_request.side_effect = [ping_resp, catalog_resp]
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryCatalogError):
            adapter.list_repositories()


class TestOciAdapterListTags:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_tags(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        tags_resp = MagicMock(status_code=200, headers={})
        tags_resp.json.return_value = {"tags": ["latest", "v1.0"]}
        mock_request.side_effect = [ping_resp, tags_resp]
        adapter = OciRegistryAdapter("reg.io")
        tags = adapter.list_tags("myapp")
        assert tags == ["latest", "v1.0"]

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_list_tags_null_tags(self, mock_request):
        ping_resp = MagicMock(status_code=200)
        tags_resp = MagicMock(status_code=200, headers={})
        tags_resp.json.return_value = {"tags": None}
        mock_request.side_effect = [ping_resp, tags_resp]
        adapter = OciRegistryAdapter("reg.io")
        tags = adapter.list_tags("myapp")
        assert tags == []


class TestOciAdapterRetry:
    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_retry_on_429(self, mock_request, mock_sleep):
        resp_429 = MagicMock(status_code=429)
        resp_200 = MagicMock(status_code=200)
        mock_request.side_effect = [resp_429, resp_200]
        adapter = OciRegistryAdapter("reg.io")
        result = adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert result.status_code == 200
        mock_sleep.assert_called_once()

    @patch("prowler.providers.image.lib.registry.base.time.sleep")
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_connection_error_retries(self, mock_request, mock_sleep):
        mock_request.side_effect = requests.exceptions.ConnectionError("failed")
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryNetworkError):
            adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert mock_request.call_count == 3

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_timeout_raises_immediately(self, mock_request):
        mock_request.side_effect = requests.exceptions.Timeout("timeout")
        adapter = OciRegistryAdapter("reg.io")
        with pytest.raises(ImageRegistryNetworkError):
            adapter._request_with_retry("GET", "https://reg.io/v2/")
        assert mock_request.call_count == 1


class TestOciAdapterNextPageUrl:
    def test_no_link_header(self):
        adapter = OciRegistryAdapter("https://reg.io")
        resp = MagicMock(headers={})
        assert adapter._next_page_url(resp) is None

    def test_link_header_with_next(self):
        adapter = OciRegistryAdapter("https://reg.io")
        resp = MagicMock(
            headers={"Link": '<https://reg.io/v2/_catalog?n=200&last=b>; rel="next"'}
        )
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo({"reg.io": "8.8.8.8"}),
        ):
            assert (
                adapter._next_page_url(resp)
                == "https://reg.io/v2/_catalog?n=200&last=b"
            )

    def test_link_header_relative_url(self):
        adapter = OciRegistryAdapter("https://reg.io")
        resp = MagicMock(
            headers={"Link": '</v2/_catalog?n=200&last=b>; rel="next"'},
            url="https://reg.io/v2/_catalog?n=200",
        )
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo({"reg.io": "8.8.8.8"}),
        ):
            assert (
                adapter._next_page_url(resp)
                == "https://reg.io/v2/_catalog?n=200&last=b"
            )

    def test_link_header_no_next(self):
        adapter = OciRegistryAdapter("https://reg.io")
        resp = MagicMock(
            headers={"Link": '<https://reg.io/v2/_catalog?n=200>; rel="prev"'}
        )
        assert adapter._next_page_url(resp) is None


class TestOutboundUrlValidator:
    """Centralized SSRF defense (PRWLRHELP-2103).

    Layers under test:
      A. Parser unification — validator and connector use the same parser.
      B. DNS resolution — reject hostnames pointing to non-public IPs.
      C. Same registrable-domain — reject realm/pagination on unrelated hosts.
    """

    # --- A: scheme + literal IP rejection ---

    def test_reject_file_scheme(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="scheme"):
            adapter._validate_outbound_url("file:///etc/passwd")

    def test_reject_ftp_scheme(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="scheme"):
            adapter._validate_outbound_url("ftp://reg.example.com/token")

    def test_reject_private_ip_literal(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter._validate_outbound_url("https://10.0.0.1/token")

    def test_reject_loopback_ip_literal(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter._validate_outbound_url("https://127.0.0.1/token")

    def test_reject_link_local_ip_literal(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter._validate_outbound_url("https://169.254.169.254/latest/meta-data")

    def test_reject_ipv6_loopback(self):
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter._validate_outbound_url("https://[::1]/token")

    # --- A: parser-mismatch bypass (the headlining PRWLRHELP-2103 PoC) ---

    def test_reject_parser_mismatch_bypass(self):
        """Reporter PoC: the literal URL parses two different ways.

        urlparse() sees host = 180.101.51.73 (public, would have been allowed)
        requests connects to 127.0.0.1:6666 (loopback)
        The validator must canonicalise via PreparedRequest and reject.
        """
        adapter = OciRegistryAdapter("reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter._validate_outbound_url(
                "http://127.0.0.1:6666\\\\@180.101.51.73/token",
                enforce_origin=False,
            )

    # --- B: DNS resolution to non-public IPs ---

    def test_reject_hostname_resolving_to_loopback(self):
        adapter = OciRegistryAdapter("https://reg.example.com")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo(
                {"reg.example.com": "8.8.8.8", "localhost": "127.0.0.1"}
            ),
        ):
            with pytest.raises(ImageRegistryAuthError, match="non-public"):
                adapter._validate_outbound_url(
                    "https://localhost/token", enforce_origin=False
                )

    def test_reject_hostname_resolving_to_metadata_ip(self):
        adapter = OciRegistryAdapter("https://reg.example.com")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo(
                {
                    "reg.example.com": "8.8.8.8",
                    "metadata.aws.internal": "169.254.169.254",
                }
            ),
        ):
            with pytest.raises(ImageRegistryAuthError, match="non-public"):
                adapter._validate_outbound_url(
                    "https://metadata.aws.internal/", enforce_origin=False
                )

    def test_unresolvable_host_passes_validator(self):
        """getaddrinfo failure is not the validator's concern — let requests fail naturally."""
        adapter = OciRegistryAdapter("https://reg.example.com")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=socket.gaierror("nope"),
        ):
            # Same eTLD+1, unresolvable — validator should not raise.
            adapter._validate_outbound_url(
                "https://nx.example.com/token", enforce_origin=True
            )

    # --- C: same registrable-domain enforcement ---

    def test_accept_same_etld1(self):
        adapter = OciRegistryAdapter("https://registry-1.docker.io")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo(
                {"registry-1.docker.io": "8.8.8.8", "auth.docker.io": "8.8.4.4"}
            ),
        ):
            canonical = adapter._validate_outbound_url("https://auth.docker.io/token")
        assert canonical == "https://auth.docker.io/token"

    def test_accept_same_host(self):
        adapter = OciRegistryAdapter("https://ghcr.io")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo({"ghcr.io": "8.8.8.8"}),
        ):
            adapter._validate_outbound_url("https://ghcr.io/token")

    def test_reject_unrelated_host(self):
        adapter = OciRegistryAdapter("https://registry-1.docker.io")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo(
                {"registry-1.docker.io": "8.8.8.8", "attacker.com": "1.1.1.1"}
            ),
        ):
            with pytest.raises(ImageRegistryAuthError, match="unrelated"):
                adapter._validate_outbound_url("https://attacker.com/token")

    def test_enforce_origin_false_allows_unrelated_public_host(self):
        """When validating the registry URL itself (the trust anchor),
        we don't compare it to itself — pass enforce_origin=False."""
        adapter = OciRegistryAdapter("https://reg.example.com")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo({"public.elsewhere.io": "8.8.8.8"}),
        ):
            adapter._validate_outbound_url(
                "https://public.elsewhere.io/", enforce_origin=False
            )

    # --- Returns canonical URL for the caller to use ---

    def test_returns_canonical_url(self):
        adapter = OciRegistryAdapter("https://ghcr.io")
        with patch(
            "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
            side_effect=_fake_getaddrinfo({"ghcr.io": "8.8.8.8"}),
        ):
            canonical = adapter._validate_outbound_url("https://ghcr.io/token")
        assert canonical == "https://ghcr.io/token"


class TestObtainBearerTokenAppliesValidator:
    """Integration: malicious Www-Authenticate realm must be rejected before the second call."""

    @patch(
        "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
        side_effect=_fake_getaddrinfo({"reg.example.com": "8.8.8.8"}),
    )
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_realm_with_parser_mismatch_payload_is_rejected(
        self, mock_request, _mock_dns
    ):
        ping_resp = MagicMock(
            status_code=401,
            headers={
                "Www-Authenticate": (
                    'Bearer realm="http://127.0.0.1:6666\\\\@180.101.51.73/token",'
                    'service="registry"'
                )
            },
        )
        mock_request.return_value = ping_resp
        adapter = OciRegistryAdapter("https://reg.example.com")
        with pytest.raises(ImageRegistryAuthError):
            adapter._ensure_auth()
        # Only the ping should have happened — not the realm GET.
        assert mock_request.call_count == 1

    @patch(
        "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
        side_effect=_fake_getaddrinfo({"reg.example.com": "8.8.8.8"}),
    )
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_realm_pointing_to_unrelated_host_is_rejected(
        self, mock_request, _mock_dns
    ):
        ping_resp = MagicMock(
            status_code=401,
            headers={"Www-Authenticate": 'Bearer realm="https://attacker.com/token"'},
        )
        mock_request.return_value = ping_resp
        adapter = OciRegistryAdapter("https://reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="unrelated"):
            adapter._ensure_auth()
        assert mock_request.call_count == 1


class TestPaginationLinkValidator:
    """The Link: rel=next URL is server-controlled and must go through the validator."""

    @patch(
        "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
        side_effect=_fake_getaddrinfo({"reg.example.com": "8.8.8.8"}),
    )
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_oci_pagination_to_unrelated_host_is_rejected(
        self, mock_request, _mock_dns
    ):
        ping_resp = MagicMock(status_code=200)
        catalog_page = MagicMock(
            status_code=200,
            headers={"Link": '<https://attacker.com/v2/_catalog?n=200>; rel="next"'},
        )
        catalog_page.json.return_value = {"repositories": ["a"]}
        mock_request.side_effect = [ping_resp, catalog_page]
        adapter = OciRegistryAdapter("https://reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="unrelated"):
            adapter.list_repositories()

    @patch(
        "prowler.providers.image.lib.registry.base.socket.getaddrinfo",
        side_effect=_fake_getaddrinfo({"reg.example.com": "8.8.8.8"}),
    )
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_oci_pagination_to_metadata_ip_is_rejected(self, mock_request, _mock_dns):
        ping_resp = MagicMock(status_code=200)
        catalog_page = MagicMock(
            status_code=200,
            headers={"Link": '<http://169.254.169.254/latest/meta-data>; rel="next"'},
        )
        catalog_page.json.return_value = {"repositories": ["a"]}
        mock_request.side_effect = [ping_resp, catalog_page]
        adapter = OciRegistryAdapter("https://reg.example.com")
        with pytest.raises(ImageRegistryAuthError, match="non-public"):
            adapter.list_repositories()


class TestCrossOriginAuthorizationStrip:
    """Bearer/Basic credentials must not leak to a host different from the registry."""

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_bearer_not_sent_to_different_host(self, mock_request):
        resp_200 = MagicMock(status_code=200)
        mock_request.return_value = resp_200
        adapter = OciRegistryAdapter("https://reg.example.com")
        adapter._bearer_token = "secret-bearer"
        # _do_authed_request — call with a different host
        adapter._do_authed_request("GET", "https://other.example.com/v2/_catalog")
        sent_headers = mock_request.call_args.kwargs.get("headers", {})
        assert "Authorization" not in sent_headers

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_bearer_is_sent_to_same_host(self, mock_request):
        resp_200 = MagicMock(status_code=200)
        mock_request.return_value = resp_200
        adapter = OciRegistryAdapter("https://reg.example.com")
        adapter._bearer_token = "secret-bearer"
        adapter._do_authed_request("GET", "https://reg.example.com/v2/_catalog")
        sent_headers = mock_request.call_args.kwargs.get("headers", {})
        assert sent_headers.get("Authorization") == "Bearer secret-bearer"

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_basic_auth_not_sent_to_different_host(self, mock_request):
        resp_200 = MagicMock(status_code=200)
        mock_request.return_value = resp_200
        adapter = OciRegistryAdapter(
            "https://reg.example.com", username="u", password="p"
        )
        adapter._basic_auth_verified = True
        adapter._do_authed_request("GET", "https://other.example.com/v2/_catalog")
        assert mock_request.call_args.kwargs.get("auth") is None


class TestOciAdapterEmptyToken:
    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_empty_bearer_token_raises(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={
                "Www-Authenticate": 'Bearer realm="https://auth.reg.io/token",service="registry"'
            },
        )
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {"token": "", "access_token": ""}
        mock_request.side_effect = [ping_resp, token_resp]
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        with pytest.raises(ImageRegistryAuthError, match="empty token"):
            adapter._ensure_auth()

    @patch("prowler.providers.image.lib.registry.base.requests.request")
    def test_none_bearer_token_raises(self, mock_request):
        ping_resp = MagicMock(
            status_code=401,
            headers={
                "Www-Authenticate": 'Bearer realm="https://auth.reg.io/token",service="registry"'
            },
        )
        token_resp = MagicMock(status_code=200)
        token_resp.json.return_value = {}
        mock_request.side_effect = [ping_resp, token_resp]
        adapter = OciRegistryAdapter("reg.io", username="u", password="p")
        with pytest.raises(ImageRegistryAuthError, match="empty token"):
            adapter._ensure_auth()


class TestOciAdapterNarrowExcept:
    def test_invalid_utf8_base64_falls_through(self):
        # Create a base64 string that decodes to invalid UTF-8
        invalid_bytes = base64.b64encode(b"\xff\xfe").decode()
        adapter = OciRegistryAdapter("ecr.aws", username="AWS", password=invalid_bytes)
        user, pwd = adapter._resolve_basic_credentials()
        assert user == "AWS"
        assert pwd == invalid_bytes


class TestCredentialRedaction:
    def test_getstate_redacts_credentials(self):
        adapter = OciRegistryAdapter(
            "reg.io", username="u", password="secret", token="tok"
        )
        state = adapter.__getstate__()
        assert state["_password"] == "***"
        assert state["_token"] == "***"
        assert state["username"] == "u"
        assert state["registry_url"] == "reg.io"

    def test_getstate_none_credentials(self):
        adapter = OciRegistryAdapter("reg.io")
        state = adapter.__getstate__()
        assert state["_password"] is None
        assert state["_token"] is None

    def test_repr_redacts_credentials(self):
        adapter = OciRegistryAdapter(
            "reg.io", username="u", password="s3cret_pw", token="s3cret_tk"
        )
        r = repr(adapter)
        assert "s3cret_pw" not in r
        assert "s3cret_tk" not in r
        assert "<redacted>" in r

    def test_properties_still_work(self):
        adapter = OciRegistryAdapter("reg.io", password="secret", token="tok")
        assert adapter.password == "secret"
        assert adapter.token == "tok"
