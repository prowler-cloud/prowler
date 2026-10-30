from types import SimpleNamespace
from unittest import mock

from werkzeug.serving import BaseWSGIServer

from dashboard.lib import startup
from dashboard.lib.startup import (
    format_ready_message,
    install_server_ready_hook,
    server_urls,
)


class TestServerUrls:
    def test_loopback_host(self):
        assert server_urls("127.0.0.1", 11666) == ("http://127.0.0.1:11666/", [])

    def test_custom_host_and_port(self):
        assert server_urls("10.0.0.5", 8080) == ("http://10.0.0.5:8080/", [])

    def test_ipv6_host_is_bracketed(self):
        assert server_urls("::1", 11666) == ("http://[::1]:11666/", [])

    def test_wildcard_host_uses_loopback_and_lists_interface(self):
        with mock.patch.object(
            startup, "get_interface_ip", return_value="192.168.1.20"
        ):
            primary, others = server_urls("0.0.0.0", 11666)
        assert primary == "http://127.0.0.1:11666/"
        assert others == ["http://192.168.1.20:11666/"]

    def test_wildcard_host_without_interface(self):
        with mock.patch.object(startup, "get_interface_ip", side_effect=OSError):
            assert server_urls("0.0.0.0", 11666) == ("http://127.0.0.1:11666/", [])

    def test_https_scheme(self):
        assert server_urls("127.0.0.1", 443, "https")[0] == "https://127.0.0.1:443/"


class TestFormatReadyMessage:
    def test_single_address(self):
        message = format_ready_message("127.0.0.1", 11666)
        assert "Prowler Local Dashboard is ready:" in message
        assert "http://127.0.0.1:11666/" in message
        assert message.endswith("Press Ctrl+C to stop.")
        assert "Also reachable" not in message
        assert "all interfaces" not in message

    def test_all_interfaces(self):
        with mock.patch.object(
            startup, "get_interface_ip", return_value="192.168.1.20"
        ):
            message = format_ready_message("0.0.0.0", 11666)
        assert "http://127.0.0.1:11666/" in message
        assert "Listening on all interfaces (0.0.0.0)." in message
        assert "Also reachable at: http://192.168.1.20:11666/" in message
        assert "http://0.0.0.0" not in message


class TestInstallServerReadyHook:
    def setup_method(self):
        self._original = BaseWSGIServer.log_startup

    def teardown_method(self):
        BaseWSGIServer.log_startup = getattr(
            BaseWSGIServer.log_startup, "_prowler_original", self._original
        )

    def test_announces_once_after_bind_and_keeps_original(self):
        printed = []
        calls = []
        BaseWSGIServer.log_startup = lambda self: calls.append(self.port)
        install_server_ready_hook(printed.append)

        server = SimpleNamespace(host="127.0.0.1", port=11667, ssl_context=None)
        BaseWSGIServer.log_startup(server)
        BaseWSGIServer.log_startup(server)

        assert calls == [11667, 11667]  # werkzeug's own startup logic still runs
        assert len(printed) == 1  # a reload or second run does not repeat it
        assert "http://127.0.0.1:11667/" in printed[0]
        assert "Press Ctrl+C to stop." in printed[0]

    def test_install_is_idempotent(self):
        first = install_server_ready_hook(lambda _: None)
        second = install_server_ready_hook(lambda _: None)
        assert first is second

    def test_failed_bind_is_never_announced(self):
        # make_server raises before log_startup is reached; nothing to announce
        printed = []
        install_server_ready_hook(printed.append)
        with mock.patch("werkzeug.serving.make_server", side_effect=OSError("in use")):
            from werkzeug.serving import run_simple

            try:
                run_simple("127.0.0.1", 1, lambda *_: [], use_reloader=False)
            except OSError:
                pass
        assert printed == []
