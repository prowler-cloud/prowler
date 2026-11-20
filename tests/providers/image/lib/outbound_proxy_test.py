import http.server
import socket
import socketserver
import threading
from unittest import mock

import pytest
import requests

from prowler.providers.image.exceptions.exceptions import ImageScanError
from prowler.providers.image.lib.outbound_proxy import TrivyOutboundProxy
from prowler.providers.image.lib.registry.base import ALLOWED_PRIVATE_NETWORKS_ENV

LOOPBACK_ALLOWED = {ALLOWED_PRIVATE_NETWORKS_ENV: "127.0.0.1/32"}


class _Ok(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"reached {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class _Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(self.request.recv(1024))


class _FakeOperatorProxy(socketserver.StreamRequestHandler):
    seen = []

    def handle(self):
        head = []
        while (line := self.rfile.readline()) not in (b"\r\n", b""):
            head.append(line)
        _FakeOperatorProxy.seen.append(head)
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        self.request.sendall(self.request.recv(1024))


def _serve(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def http_upstream():
    server = _serve(http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Ok))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def echo_upstream():
    server = _serve(socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Echo))
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _connect(proxy, authority, payload=b"ping"):
    host, port = proxy.url.removeprefix("http://").split(":")
    with socket.create_connection((host, int(port)), timeout=5) as client:
        client.sendall(
            f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode()
        )
        reply = client.recv(1024)
        if b" 200 " not in reply.split(b"\r\n", 1)[0]:
            return reply, b""
        client.sendall(payload)
        return reply, client.recv(1024)


def _get(url, proxy):
    with requests.Session() as session:
        # an inherited NO_PROXY would send the request around the proxy under test
        session.trust_env = False
        return session.get(url, proxies={"http": proxy.url}, timeout=5)


def _resolves(mapping):
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host in mapping:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
        return real(host, *args, **kwargs)

    return mock.patch.object(socket, "getaddrinfo", side_effect=fake)


class TestTrivyOutboundProxy:
    def test_forwards_a_plain_http_request_to_an_allowlisted_address(
        self, http_upstream
    ):
        with TrivyOutboundProxy(LOOPBACK_ALLOWED) as proxy:
            response = _get(f"http://127.0.0.1:{http_upstream}/v2/", proxy)

        assert response.status_code == 200
        assert response.text == "reached /v2/"
        assert response.headers["Connection"] == "close"

    def test_refuses_a_hostname_that_resolves_to_a_private_address(self, http_upstream):
        with _resolves({"registry.attacker.example": "127.0.0.1"}):
            with TrivyOutboundProxy({}) as proxy:
                response = _get(
                    f"http://registry.attacker.example:{http_upstream}/token", proxy
                )

        assert response.status_code == 403
        assert "127.0.0.1" in response.text
        assert "reached" not in response.text

    def test_refuses_a_tunnel_to_the_metadata_address(self):
        with TrivyOutboundProxy({}) as proxy:
            reply, _ = _connect(proxy, "169.254.169.254:443")

        assert reply.startswith(b"HTTP/1.1 403 ")

    def test_refuses_a_tunnel_to_a_hostname_with_one_private_answer(self):
        real = socket.getaddrinfo

        def split_horizon(host, *args, **kwargs):
            if host == "split.example":
                return [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0)),
                ]
            return real(host, *args, **kwargs)

        with mock.patch.object(socket, "getaddrinfo", side_effect=split_horizon):
            with TrivyOutboundProxy({}) as proxy:
                reply, _ = _connect(proxy, "split.example:443")

        assert reply.startswith(b"HTTP/1.1 403 ")

    def test_tunnels_to_an_allowlisted_address(self, echo_upstream):
        with TrivyOutboundProxy(LOOPBACK_ALLOWED) as proxy:
            reply, echoed = _connect(proxy, f"127.0.0.1:{echo_upstream}")

        assert reply.startswith(b"HTTP/1.1 200 ")
        assert echoed == b"ping"

    def test_dials_the_vetted_address_rather_than_resolving_again(self, echo_upstream):
        dialed = []
        real_connect = socket.create_connection

        def spy(address, *args, **kwargs):
            dialed.append(address)
            return real_connect(address, *args, **kwargs)

        with _resolves({"registry.example": "127.0.0.1"}):
            with mock.patch.object(socket, "create_connection", side_effect=spy):
                with TrivyOutboundProxy(LOOPBACK_ALLOWED) as proxy:
                    _connect(proxy, f"registry.example:{echo_upstream}")

        assert ("127.0.0.1", echo_upstream) in dialed
        assert all(host != "registry.example" for host, _ in dialed)

    def test_chains_through_the_operator_proxy_after_vetting(self):
        _FakeOperatorProxy.seen = []
        operator = _serve(
            socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeOperatorProxy)
        )
        environ = {
            "HTTPS_PROXY": f"http://user:p%40ss@127.0.0.1:{operator.server_address[1]}"  # trufflehog:ignore
        }
        try:
            with TrivyOutboundProxy(environ) as proxy:
                reply, echoed = _connect(proxy, "8.8.8.8:443")
        finally:
            operator.shutdown()
            operator.server_close()

        assert reply.startswith(b"HTTP/1.1 200 ")
        assert echoed == b"ping"
        head = _FakeOperatorProxy.seen[0]
        assert head[0].startswith(b"CONNECT 8.8.8.8:443 ")
        assert b"Proxy-Authorization: Basic dXNlcjpwQHNz\r\n" in head

    def test_does_not_chain_a_request_the_check_refuses(self):
        environ = {"HTTPS_PROXY": "http://127.0.0.1:9"}
        with TrivyOutboundProxy(environ) as proxy:
            reply, _ = _connect(proxy, "10.0.0.5:443")

        assert reply.startswith(b"HTTP/1.1 403 ")

    def test_route_points_every_proxy_variable_at_itself_and_drops_no_proxy(self):
        environ = {
            "PATH": "/usr/bin",
            "HTTPS_PROXY": "http://operator:3128",
            "NO_PROXY": "169.254.169.254,10.0.0.0/8",
            "no_proxy": "localhost",
        }
        proxy = TrivyOutboundProxy({})
        try:
            routed = proxy.route(environ)
        finally:
            proxy._server.server_close()

        assert routed["PATH"] == "/usr/bin"
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            assert routed[key] == proxy.url
        assert "NO_PROXY" not in routed
        assert "no_proxy" not in routed
        assert proxy.url.startswith("http://127.0.0.1:")


class _FakeOperatorHttpProxy(socketserver.StreamRequestHandler):
    seen = []

    def handle(self):
        head = []
        while (line := self.rfile.readline()) not in (b"\r\n", b""):
            head.append(line)
        _FakeOperatorHttpProxy.seen.append(head)
        self.wfile.write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: keep-alive\r\n\r\n"
            b"via-op!"
        )


class TestTrivyOutboundProxyOperatorProxy:
    def test_forwards_plain_http_through_the_operator_proxy_in_absolute_form(self):
        _FakeOperatorHttpProxy.seen = []
        operator = _serve(
            socketserver.ThreadingTCPServer(("127.0.0.1", 0), _FakeOperatorHttpProxy)
        )
        environ = {"HTTP_PROXY": f"127.0.0.1:{operator.server_address[1]}"}
        try:
            with TrivyOutboundProxy(environ) as proxy:
                response = _get("http://8.8.8.8/v2/", proxy)
        finally:
            operator.shutdown()
            operator.server_close()

        assert response.text == "via-op!"
        assert response.headers["Connection"] == "close"
        head = _FakeOperatorHttpProxy.seen[0]
        assert head[0] == b"GET http://8.8.8.8/v2/ HTTP/1.1\r\n"
        assert b"Connection: close\r\n" in head

    def test_dials_directly_a_host_listed_in_the_operator_no_proxy(self, echo_upstream):
        environ = {
            **LOOPBACK_ALLOWED,
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "127.0.0.1",
        }
        with TrivyOutboundProxy(environ) as proxy:
            reply, echoed = _connect(proxy, f"127.0.0.1:{echo_upstream}")

        assert reply.startswith(b"HTTP/1.1 200 ")
        assert echoed == b"ping"

    def test_answers_502_when_the_operator_proxy_is_unreachable(self):
        with TrivyOutboundProxy({"HTTPS_PROXY": "http://127.0.0.1:9"}) as proxy:
            reply, _ = _connect(proxy, "8.8.8.8:443")

        assert reply.startswith(b"HTTP/1.1 502 ")

    @pytest.mark.parametrize(
        "proxy_url", ["socks5://proxy.example:1080", "https://proxy.example:3128"]
    )
    def test_refuses_an_operator_proxy_it_cannot_speak(self, proxy_url):
        with pytest.raises(ImageScanError, match="only an http:// proxy"):
            TrivyOutboundProxy({"HTTPS_PROXY": proxy_url})


class TestTrivyOutboundProxyMalformedRequests:
    def test_answers_400_to_a_non_numeric_content_length(self):
        with TrivyOutboundProxy({}) as proxy:
            host, port = proxy.url.removeprefix("http://").split(":")
            with socket.create_connection((host, int(port)), timeout=5) as client:
                client.sendall(
                    b"POST http://8.8.8.8/ HTTP/1.1\r\nContent-Length: abc\r\n\r\n"
                )
                reply = client.recv(1024)

        assert reply.startswith(b"HTTP/1.1 400 ")

    def test_answers_400_to_a_connect_without_a_port(self):
        with TrivyOutboundProxy({}) as proxy:
            reply, _ = _connect(proxy, "8.8.8.8")

        assert reply.startswith(b"HTTP/1.1 400 ")
