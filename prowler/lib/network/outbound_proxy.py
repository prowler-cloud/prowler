"""Loopback forward proxy that keeps Trivy's connections off non-public addresses."""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import select
import socket
import socketserver
import threading
from urllib.parse import SplitResult, unquote, urlsplit

from prowler.lib.logger import logger
from prowler.lib.network.ssrf import OutboundURLNotAllowedError, _ip_is_non_public

PROXY_ENV_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
NO_PROXY_ENV_VARS = ("NO_PROXY", "no_proxy")

_MAX_HEAD_BYTES = 64 * 1024
_CONNECT_TIMEOUT = 30
_IDLE_TIMEOUT = 300
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailer",
        "upgrade",
    }
)


class _Refused(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _read_head(stream) -> list[bytes]:
    lines, size = [], 0
    while True:
        line = stream.readline(_MAX_HEAD_BYTES + 1)
        size += len(line)
        if size > _MAX_HEAD_BYTES:
            raise _Refused(431, "Request head too large")
        if line in (b"\r\n", b"\n", b""):
            return lines
        lines.append(line)


def _header_items(lines: list[bytes]) -> list[tuple[str, str]]:
    items = []
    for line in lines:
        name, _, value = line.decode("latin-1").partition(":")
        items.append((name.strip(), value.strip()))
    return items


def _authority(address: str, port: int) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def _no_proxy_matches(no_proxy: str, host: str, port: int) -> bool:
    """Whether host:port is excluded from the operator proxy, as Go matches NO_PROXY."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    for entry in (item.strip().lower() for item in no_proxy.split(",")):
        if not entry:
            continue
        if entry == "*":
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            pass
        else:
            if literal and literal.version == network.version and literal in network:
                return True
            continue
        name, _, entry_port = entry.partition(":")
        if entry_port and entry_port != str(port):
            continue
        name = name.lstrip("*").lstrip(".")
        if name and (host.lower() == name or host.lower().endswith(f".{name}")):
            return True
    return False


def _relay(client: socket.socket, upstream: socket.socket) -> None:
    peers = {client: upstream, upstream: client}
    while True:
        readable, _, _ = select.select(list(peers), [], [], _IDLE_TIMEOUT)
        if not readable:
            return
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            peers[source].sendall(data)


class _Handler(socketserver.StreamRequestHandler):
    server: _GuardServer
    timeout = _IDLE_TIMEOUT

    def setup(self) -> None:
        super().setup()
        self.server.track(self.connection)

    def finish(self) -> None:
        try:
            super().finish()
        finally:
            self.server.untrack(self.connection)

    def handle(self) -> None:
        try:
            head = _read_head(self.rfile)
            if not head:
                return
            request_line = head[0].decode("latin-1").strip().split(" ")
            if len(request_line) != 3:
                raise _Refused(400, "Malformed request line")
            method, target, _ = request_line
            headers = _header_items(head[1:])
            if method == "CONNECT":
                self._tunnel(target)
            else:
                self._forward(method, target, headers)
        except _Refused as refusal:
            logger.warning(f"Outbound proxy refused a Trivy request: {refusal.reason}")
            self._reply(refusal.status, refusal.reason)
        except ValueError:
            self._reply(400, "Malformed request")
        except OSError as error:
            logger.debug(f"Outbound proxy connection ended: {error}")

    def _reply(self, status: int, reason: str) -> None:
        body = reason.encode()
        try:
            self.wfile.write(
                f"HTTP/1.1 {status} Refused\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
        except OSError:
            pass

    def _tunnel(self, authority: str) -> None:
        parts = urlsplit(f"//{authority}")
        if not parts.hostname or not parts.port:
            raise _Refused(400, "CONNECT needs host:port")
        upstream = self.server.dial("https", parts.hostname, parts.port)
        with self.server.holding(upstream.socket):
            if upstream.via_proxy:
                pinned = _authority(upstream.address, parts.port)
                upstream.socket.sendall(
                    f"CONNECT {pinned} HTTP/1.1\r\nHost: {pinned}\r\n".encode()
                    + upstream.proxy_auth_header
                    + b"\r\n"
                )
                reply = _read_head(upstream.socket.makefile("rb"))
                if not reply or b" 200" not in reply[0]:
                    raise _Refused(502, "Upstream proxy refused the tunnel")
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
            _relay(self.connection, upstream.socket)

    def _forward(self, method: str, target: str, headers: list) -> None:
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            raise _Refused(400, "Only absolute http:// targets are forwarded")
        if any(
            name.lower() == "transfer-encoding" and value.lower() != "identity"
            for name, value in headers
        ):
            raise _Refused(501, "Chunked request bodies are not forwarded")
        length = next(
            (int(value) for name, value in headers if name.lower() == "content-length"),
            0,
        )

        port = parts.port or 80
        upstream = self.server.dial("http", parts.hostname, port)
        with self.server.holding(upstream.socket):
            request_target = parts.path or "/"
            if parts.query:
                request_target += f"?{parts.query}"
            if upstream.via_proxy:
                # the vetted address, not the name the operator's proxy would resolve
                request_target = (
                    f"http://{_authority(upstream.address, port)}{request_target}"
                )
            kept = "".join(
                f"{name}: {value}\r\n"
                for name, value in headers
                if name.lower() not in _HOP_BY_HOP
            )
            if not any(name.lower() == "host" for name, _ in headers):
                kept += f"Host: {parts.netloc.rpartition('@')[2]}\r\n"
            upstream.socket.sendall(
                f"{method} {request_target} HTTP/1.1\r\n{kept}".encode("latin-1")
                + upstream.proxy_auth_header
                + b"Connection: close\r\n\r\n"
            )
            if length:
                upstream.socket.sendall(self.rfile.read(length))

            # one request per client connection: Go reuses a proxy connection
            # across hosts, so a kept-alive one would carry the next request to
            # the host already dialed
            response = upstream.socket.makefile("rb")
            head = _read_head(response)
            if not head:
                return
            kept = b"".join(
                line
                for line in head[1:]
                if line.split(b":", 1)[0].strip().lower().decode("latin-1")
                not in _HOP_BY_HOP
            )
            self.wfile.write(head[0] + kept + b"Connection: close\r\n\r\n")
            while chunk := response.read1(65536):
                self.wfile.write(chunk)


class _Upstream:
    def __init__(
        self,
        sock: socket.socket,
        address: str,
        via_proxy: bool,
        proxy_auth_header: bytes = b"",
    ) -> None:
        self.socket = sock
        self.address = address
        self.via_proxy = via_proxy
        self.proxy_auth_header = proxy_auth_header


def _operator_proxy(raw: str | None) -> SplitResult | None:
    if not raw:
        return None
    unsupported = OutboundURLNotAllowedError(
        "With the outbound host check enabled, Trivy scans support only a valid "
        "http:// proxy URL in HTTP_PROXY and HTTPS_PROXY"
    )
    try:
        proxy = urlsplit(raw if "://" in raw else f"http://{raw}")
        proxy.port  # raises on a malformed port
    except ValueError as error:
        # the URL can carry the proxy credentials, so it stays out of the message
        raise unsupported from error
    if proxy.scheme != "http" or not proxy.hostname:
        raise unsupported
    return proxy


class _GuardServer(socketserver.ThreadingTCPServer):
    daemon_threads = True

    def __init__(
        self, environ: dict, allowed_networks: tuple, allowlist_env: str
    ) -> None:
        self.allowed_networks = allowed_networks
        self.allowlist_env = allowlist_env
        self.upstream_proxies = {
            scheme: _operator_proxy(
                environ.get(f"{scheme.upper()}_PROXY") or environ.get(f"{scheme}_proxy")
            )
            for scheme in ("http", "https")
        }
        self.no_proxy = environ.get("NO_PROXY") or environ.get("no_proxy") or ""
        self._open_sockets: set = set()
        self._open_sockets_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def track(self, sock: socket.socket) -> None:
        with self._open_sockets_lock:
            self._open_sockets.add(sock)

    def untrack(self, sock: socket.socket) -> None:
        with self._open_sockets_lock:
            self._open_sockets.discard(sock)

    @contextlib.contextmanager
    def holding(self, sock: socket.socket):
        try:
            yield sock
        finally:
            sock.close()
            self.untrack(sock)

    def close_open_sockets(self) -> None:
        """Unblock handlers still relaying once the subprocess is done."""
        with self._open_sockets_lock:
            open_sockets = list(self._open_sockets)
        for sock in open_sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def _allowlisted(self, address: str) -> bool:
        parsed = ipaddress.ip_address(address)
        return any(
            parsed.version == network.version and parsed in network
            for network in self.allowed_networks
        )

    def vetted_addresses(self, host: str) -> list[str]:
        """Addresses of host, refusing it if any of them is non-public."""
        try:
            ipaddress.ip_address(host)
            addresses = [host]
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            except socket.gaierror:
                raise _Refused(502, f"Could not resolve host {host!r}")
            addresses = list(dict.fromkeys(sockaddr[0] for *_, sockaddr in infos))
        for address in addresses:
            if _ip_is_non_public(address) and not self._allowlisted(address):
                raise _Refused(
                    403,
                    f"Host {host!r} resolves to non-public address {address}. "
                    f"To reach a private network, list the trusted ranges in "
                    f"{self.allowlist_env}.",
                )
        return addresses

    def dial(self, scheme: str, host: str, port: int) -> _Upstream:
        """Connect to a vetted address of host, or through the operator's proxy."""
        addresses = self.vetted_addresses(host)

        proxy = self.upstream_proxies.get(scheme)
        if proxy and not _no_proxy_matches(self.no_proxy, host, port):
            auth = b""
            if proxy.username:
                credentials = (
                    f"{unquote(proxy.username)}:{unquote(proxy.password or '')}"
                )
                auth = (
                    b"Proxy-Authorization: Basic "
                    + base64.b64encode(credentials.encode())
                    + b"\r\n"
                )
            try:
                sock = socket.create_connection(
                    (proxy.hostname, proxy.port or 80), timeout=_CONNECT_TIMEOUT
                )
            except OSError as error:
                raise _Refused(502, f"Could not reach the configured proxy: {error}")
            sock.settimeout(_IDLE_TIMEOUT)
            self.track(sock)
            return _Upstream(sock, addresses[0], via_proxy=True, proxy_auth_header=auth)

        last_error = None
        for address in addresses:
            try:
                sock = socket.create_connection(
                    (address, port), timeout=_CONNECT_TIMEOUT
                )
            except OSError as error:
                last_error = error
                continue
            sock.settimeout(_IDLE_TIMEOUT)
            self.track(sock)
            return _Upstream(sock, address, via_proxy=False)
        raise _Refused(502, f"Could not connect to {host!r}: {last_error}")


class TrivyOutboundProxy:
    """Route a Trivy subprocess through a proxy that refuses non-public addresses.

    Trivy refuses redirects and token realms to private IP literals but not to
    hostnames that resolve to one; this proxy resolves and checks every host it
    is asked to reach.
    """

    def __init__(
        self, environ: dict, allowed_networks: tuple = (), allowlist_env: str = ""
    ) -> None:
        self._server = _GuardServer(environ, allowed_networks, allowlist_env)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="trivy-outbound-proxy", daemon=True
        )

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def route(self, environ: dict) -> dict:
        """Copy of environ that sends every Trivy connection through this proxy."""
        routed = {
            key: value
            for key, value in environ.items()
            if key not in PROXY_ENV_VARS + NO_PROXY_ENV_VARS
        }
        for key in PROXY_ENV_VARS:
            routed[key] = self.url
        return routed

    def start(self) -> None:
        """Serve in a background thread; the listener is closed if that fails."""
        try:
            self._thread.start()
        except RuntimeError as error:
            self._server.server_close()
            raise OSError(
                f"Could not start the outbound proxy thread: {error}"
            ) from error

    def stop(self) -> None:
        if self._thread.is_alive():
            self._server.shutdown()
        self._server.server_close()
        self._server.close_open_sockets()

    def __enter__(self) -> TrivyOutboundProxy:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()
