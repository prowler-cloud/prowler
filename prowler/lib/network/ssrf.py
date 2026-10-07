"""Outbound URL validation for provider connection tests."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from urllib.parse import urlparse

from prowler.lib.logger import logger

ALLOWED_PRIVATE_NETWORKS_ENV = "PROWLER_ALLOWED_PRIVATE_NETWORKS"

_NON_PUBLIC_IP_PROPERTIES = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_multicast",
    "is_reserved",
    "is_unspecified",
)

# scp-like git remotes (user@host:path) carry no scheme, so urlparse cannot read them
_SCP_LIKE_REMOTE = re.compile(r"^(?:[^@/]+@)?(?P<host>[^:/]+):(?!//)")

_NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")


class OutboundURLNotAllowedError(Exception):
    """A supplied URL points at a destination the worker must not reach."""


def _parse_allowed_networks(raw: str | None) -> tuple:
    if not raw or not raw.strip():
        return ()
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as error:
            raise OutboundURLNotAllowedError(
                f"Malformed entry {entry!r} in {ALLOWED_PRIVATE_NETWORKS_ENV}: {error}"
            )
    return tuple(networks)


def allowed_private_networks() -> tuple:
    """Operator-configured private networks the SSRF guard must not block."""
    networks = _parse_allowed_networks(os.environ.get(ALLOWED_PRIVATE_NETWORKS_ENV))
    if networks:
        logger.warning(
            f"{ALLOWED_PRIVATE_NETWORKS_ENV} is set — SSRF protection relaxed for private networks: "
            + ", ".join(str(network) for network in networks)
        )
    return networks


def _unwrap_ipv6(address: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    if not isinstance(address, ipaddress.IPv6Address):
        return address
    embedded = address.ipv4_mapped or address.sixtofour
    if embedded is None and address in _NAT64_WELL_KNOWN_PREFIX:
        embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return embedded or address


def _ip_is_non_public(address: str) -> bool:
    try:
        parsed = _unwrap_ipv6(ipaddress.ip_address(address))
    except ValueError:
        return False
    # is_global is the broad check; the properties stay because some multicast
    # ranges report is_global and would otherwise slip through
    if not parsed.is_global:
        return True
    return any(getattr(parsed, prop) for prop in _NON_PUBLIC_IP_PROPERTIES)


def _ip_is_allowlisted(address: str, networks: tuple) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(
        parsed.version == network.version and parsed in network for network in networks
    )


def _resolve(host: str) -> set:
    try:
        return {sockaddr[0] for *_, sockaddr in socket.getaddrinfo(host, None)}
    except socket.gaierror as error:
        raise OutboundURLNotAllowedError(f"Could not resolve host {host!r}: {error}")


def extract_host(url: str) -> str:
    """Host of a URL, accepting scp-like git remotes that carry no scheme."""
    scp_like = _SCP_LIKE_REMOTE.match(url)
    if scp_like and "://" not in url:
        return scp_like.group("host")
    host = urlparse(url).hostname
    if not host:
        raise OutboundURLNotAllowedError(f"Could not read a host from URL {url!r}")
    return host


def validate_outbound_host(host: str) -> None:
    """Reject a host that is, or resolves to, a non-public address.

    Resolution happens here and again inside the client that connects, so a
    hostile DNS server can still answer differently the second time.
    """
    networks = allowed_private_networks()

    try:
        ipaddress.ip_address(host)
    except ValueError:
        addresses = _resolve(host)
    else:
        addresses = {host}

    for address in addresses:
        if _ip_is_non_public(address) and not _ip_is_allowlisted(address, networks):
            raise OutboundURLNotAllowedError(
                f"Host {host!r} resolves to non-public address {address} and cannot be "
                f"reached. To scan a target on a private network, list the trusted "
                f"ranges in the {ALLOWED_PRIVATE_NETWORKS_ENV} environment variable of "
                f"the process running the scan"
            )


def validate_outbound_url(
    url: str, *, allowed_schemes: tuple = ("http", "https")
) -> None:
    """Reject a URL whose scheme is not allowed or whose host is not public."""
    scheme = urlparse(url).scheme
    if scheme and scheme not in allowed_schemes:
        raise OutboundURLNotAllowedError(
            f"Disallowed URL scheme {scheme!r}. Allowed: {', '.join(allowed_schemes)}"
        )
    validate_outbound_host(extract_host(url))
