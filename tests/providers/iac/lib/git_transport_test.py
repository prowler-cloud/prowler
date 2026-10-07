import http.server
import threading

import pytest

from prowler.lib.network.ssrf import (
    ALLOWED_PRIVATE_NETWORKS_ENV,
    OutboundURLNotAllowedError,
)
from prowler.providers.iac.lib.git_transport import ls_remote

LINK_LOCAL_TARGET = "http://169.254.169.254/evil/info/refs?service=git-upload-pack"


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
