import http.server
import socket
import threading
from unittest import mock

import pytest
from dulwich.config import ConfigDict

from prowler.lib.network.ssrf import (
    ALLOWED_PRIVATE_NETWORKS_ENV,
    OutboundURLNotAllowedError,
    validate_outbound_url,
)
from prowler.providers.iac.lib import git_transport
from prowler.providers.iac.lib.git_transport import ls_remote

LINK_LOCAL_TARGET = "http://169.254.169.254/evil/info/refs?service=git-upload-pack"


def _resolves_to(*addresses):
    return mock.patch.object(
        socket,
        "getaddrinfo",
        return_value=[(2, 1, 6, "", (address, 0)) for address in addresses],
    )


class _Recorder:
    def __init__(self):
        self.requests = []
        self.redirect_to = None


def _server(recorder):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            recorder.requests.append((self.path, self.headers.get("Authorization")))
            if recorder.redirect_to:
                self.send_response(302)
                self.send_header("Location", recorder.redirect_to)
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, *_args):
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


@pytest.fixture
def origin():
    recorder = _Recorder()
    httpd = _server(recorder)
    recorder.port = httpd.server_address[1]
    recorder.url = f"http://127.0.0.1:{recorder.port}"
    yield recorder
    httpd.shutdown()


@pytest.fixture
def final():
    recorder = _Recorder()
    httpd = _server(recorder)
    recorder.port = httpd.server_address[1]
    recorder.url = f"http://127.0.0.1:{recorder.port}"
    yield recorder
    httpd.shutdown()


@pytest.fixture(autouse=True)
def allow_loopback(monkeypatch):
    # the servers run on loopback, so the guard has to be told to allow it;
    # the redirect targets under test are judged by the same allowlist
    monkeypatch.setenv(ALLOWED_PRIVATE_NETWORKS_ENV, "127.0.0.1/32")


class TestLsRemote:
    def test_rejects_a_redirect_to_a_non_public_address(self, origin):
        origin.redirect_to = LINK_LOCAL_TARGET

        with pytest.raises(OutboundURLNotAllowedError):
            ls_remote(f"{origin.url}/repo.git")

        assert len(origin.requests) == 1

    def test_follows_a_redirect_to_an_allowed_address(self, origin, final):
        origin.redirect_to = f"{final.url}/moved/info/refs?service=git-upload-pack"

        # the final server answers 404, so dulwich reports not a repository
        # rather than a rejection: the hop was allowed and followed
        with pytest.raises(Exception) as outcome:
            ls_remote(f"{origin.url}/repo.git")

        assert not isinstance(outcome.value, OutboundURLNotAllowedError)
        assert len(final.requests) == 1

    def test_keeps_sending_the_url_credentials(self, origin):
        """A supplied pool manager must not cost dulwich its userinfo authentication."""
        with pytest.raises(Exception):
            ls_remote(f"http://x-access-token:a-token@127.0.0.1:{origin.port}/repo.git")

        assert origin.requests[0][1] is not None


class TestEffectiveDestination:
    def test_rejects_a_private_host_an_insteadof_rule_rewrites_to(self, monkeypatch):
        """git rewrites the URL before dulwich picks the transport.

        The supplied host resolves public on purpose, so only the rewrite can
        make this fail.
        """
        config = ConfigDict()
        config.set(
            (b"url", b"ssh://10.0.0.5/"), b"insteadOf", b"https://reg.example.com/"
        )
        monkeypatch.setattr(git_transport, "git_config", lambda: config)

        with _resolves_to("140.82.121.4"):
            with pytest.raises(OutboundURLNotAllowedError, match="non-public"):
                git_transport.ls_remote("https://reg.example.com/org/repo.git")

    @pytest.mark.parametrize(
        "url,expected",
        [
            (
                "https://user:a-token@github.com:8443/o/r.git",
                "https://github.com:8443/o/r.git",
            ),
            # the path stays: an http.<url>.* section can be path-specific
            ("https://user:a-token@github.com/o/r.git", "https://github.com/o/r.git"),
            # urlparse drops the brackets of an IPv6 literal
            ("https://user:a-token@[::1]:8443/o/r.git", "https://[::1]:8443/o/r.git"),
            # nothing to strip, so nothing is rewritten
            (
                "https://[2606:4700:4700::1111]/o/r.git",
                "https://[2606:4700:4700::1111]/o/r.git",
            ),
        ],
    )
    def test_strips_only_the_credentials_from_the_proxy_base_url(self, url, expected):
        assert git_transport.proxy_base_url(url) == expected

    @pytest.mark.parametrize("scheme", ["http", "https", "ssh", "git+ssh", "git"])
    def test_allows_every_scheme_dulwich_can_transport(self, scheme, monkeypatch):
        """A scheme dulwich routes must reach the host check, not be refused on scheme."""
        monkeypatch.setattr(git_transport, "git_config", ConfigDict)

        with _resolves_to("140.82.121.4"):
            # the scheme must not be what rejects it; a public host is accepted
            validate_outbound_url(
                f"{scheme}://host.example/o/r.git",
                allowed_schemes=git_transport.ALLOWED_SCHEMES,
            )

    def test_honours_a_no_proxy_bypass(self, monkeypatch, origin):
        """Built without base_url, dulwich cannot see no_proxy and uses the proxy."""
        monkeypatch.setenv("http_proxy", "http://127.0.0.1:1")
        monkeypatch.setenv("no_proxy", "127.0.0.1")

        with pytest.raises(Exception):
            git_transport.ls_remote(f"{origin.url}/repo.git")

        assert len(origin.requests) == 1
