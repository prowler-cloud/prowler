"""Startup output helpers for `prowler dashboard`.

The local URL is announced only once the HTTP server is listening. Werkzeug
calls ``BaseWSGIServer.log_startup`` right after it binds the socket, so a
thin wrapper around that method reads the effective host and port from the
bound server and prints the ready message. Dash silences the Werkzeug logger
below ERROR while in debug mode, so hooking the method (not the log) is what
makes the announcement reliable. Werkzeug's own behaviour is untouched: the
original method still runs and no logger is reconfigured.
"""

import logging
import socket

from colorama import Fore, Style
from werkzeug.serving import BaseWSGIServer, get_interface_ip

from prowler.config.config import banner_color

_WILDCARD_HOSTS = {"0.0.0.0": "127.0.0.1", "::": "[::1]"}


def server_urls(host, port, scheme="http"):
    """Return the browser URL and the other reachable URLs for a bound server.

    A wildcard host (``0.0.0.0`` or ``::``) is never presented as a browser
    destination: the loopback address is used instead and the interface
    address is listed as also reachable.
    """
    if host in _WILDCARD_HOSTS:
        primary = f"{scheme}://{_WILDCARD_HOSTS[host]}:{port}/"
        family = socket.AF_INET if host == "0.0.0.0" else socket.AF_INET6
        try:
            interface_ip = get_interface_ip(family)
        except OSError:
            interface_ip = None
        others = []
        if interface_ip:
            if ":" in interface_ip:
                interface_ip = f"[{interface_ip}]"
            others.append(f"{scheme}://{interface_ip}:{port}/")
        return primary, others
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{scheme}://{display_host}:{port}/", []


def format_ready_message(host, port, scheme="http"):
    """Render the ready block, styled like the CLI banner, for a listening server."""
    primary, others = server_urls(host, port, scheme)
    bar = f"{banner_color}│{Style.RESET_ALL}"
    check = f"{Fore.GREEN}✓{Style.RESET_ALL}"
    lines = [
        f"{bar} {check} {Style.BRIGHT}Prowler Local Dashboard now is running on{Style.RESET_ALL} "
        f"{banner_color}{primary}{Style.RESET_ALL}"
    ]
    if host in _WILDCARD_HOSTS:
        lines.append(f"{bar}   Listening on all interfaces ({host}).")
    if others:
        lines.append(f"{bar}   Also reachable at: " + ", ".join(others))
    lines.append(f"{bar} Press Ctrl+C to stop.")
    return "\n".join(lines)


class DashRunningLineFilter(logging.Filter):
    """Drop Dash's own ``Dash is running on ...`` line from the app logger.

    The ready block printed by ``install_server_ready_hook`` already states the
    effective URL once the server is listening, so Dash's pre-bind line would
    only repeat it. Every other record on the logger still passes.
    """

    def filter(self, record):
        return not record.getMessage().startswith("Dash is running on")


def silence_dash_running_line(app):
    """Attach ``DashRunningLineFilter`` to a Dash app's logger once."""
    if not any(isinstance(f, DashRunningLineFilter) for f in app.logger.filters):
        app.logger.addFilter(DashRunningLineFilter())


def _print_now(message):
    """Print and flush so the ready message shows even when stdout is piped."""
    print(message, flush=True)


def install_server_ready_hook(announce=_print_now):
    """Announce the effective address right after Werkzeug binds the socket.

    Wraps ``BaseWSGIServer.log_startup`` once per process. The wrapper calls
    the original method first, so Werkzeug's own startup output is unchanged,
    then prints the ready block a single time. A failed bind never reaches
    ``log_startup``, so a startup error is never announced as ready.
    """
    if getattr(BaseWSGIServer.log_startup, "_prowler_ready_hook", False):
        return BaseWSGIServer.log_startup

    original = BaseWSGIServer.log_startup
    state = {"announced": False}

    def log_startup(self):
        original(self)
        if state["announced"]:
            return
        state["announced"] = True
        scheme = "http" if self.ssl_context is None else "https"
        announce("\n" + format_ready_message(self.host, self.port, scheme) + "\n")

    log_startup._prowler_ready_hook = True
    log_startup._prowler_original = original
    BaseWSGIServer.log_startup = log_startup
    return log_startup
