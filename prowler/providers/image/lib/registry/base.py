"""Registry adapter abstract base class."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import time
from abc import ABC, abstractmethod
from urllib.parse import urljoin, urlparse

import requests
import tldextract

from prowler.config.config import prowler_version
from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import (
    ImageInvalidAllowedNetworksError,
    ImageRegistryAuthError,
    ImageRegistryNetworkError,
)

_MAX_RETRIES = 3
_MAX_REDIRECTS = 5
# a registry legitimately redirects: Docker Hub sends blob pulls to a CDN and a
# renamed repository answers 301, so each hop is validated rather than refused
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_BACKOFF_BASE = 1
_USER_AGENT = f"Prowler/{prowler_version} (registry-adapter)"

_ALLOWLIST_HINT = (
    "To scan a registry on a private network, list the trusted ranges in "
    "PROWLER_IMAGE_PROVIDER_ALLOWED_PRIVATE_NETWORKS."
)

# Same variable the shared guard reads; `prowler/__main__.py` sets it so the CLI,
# where the operator supplies the registry themselves, is not refused its own
# private network. Unset means the check runs, so a missing setting fails safe.
SKIP_OUTBOUND_CHECK_ENV = "PROWLER_SKIP_OUTBOUND_HOST_CHECK"

_TRUTHY = {"1", "true", "yes", "on"}

_NON_PUBLIC_IP_PROPERTIES = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_multicast",
    "is_reserved",
    "is_unspecified",
)


def _outbound_check_skipped() -> bool:
    return os.environ.get(SKIP_OUTBOUND_CHECK_ENV, "").strip().lower() in _TRUTHY


def _ip_is_non_public(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # is_global is the broad check; the properties stay because some multicast
    # ranges report is_global and would otherwise slip through
    if not addr.is_global:
        return True
    return any(getattr(addr, prop) for prop in _NON_PUBLIC_IP_PROPERTIES)


def _registrable_domain(host: str) -> str | None:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


ALLOWED_PRIVATE_NETWORKS_ENV = "PROWLER_IMAGE_PROVIDER_ALLOWED_PRIVATE_NETWORKS"


def _parse_allowed_private_networks(
    raw: str | None,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse the comma-separated IP/CIDR allowlist; malformed entries fail loudly."""
    if raw is None or not raw.strip():
        return ()
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ImageInvalidAllowedNetworksError(
                file=__file__,
                message=f"Malformed entry {entry!r} in {ALLOWED_PRIVATE_NETWORKS_ENV}: {exc}",
            )
    return tuple(networks)


# 307 and 308 are the two that must replay the request unchanged
_BODY_PRESERVING_REDIRECTS = frozenset({307, 308})
_BODY_OPTIONS = ("data", "json", "files")
_BODY_HEADERS = ("content-length", "content-type", "transfer-encoding")


def _rebuilt_method(method: str, status_code: int) -> str:
    """How ``requests`` rewrites the method on a redirect (RFC 7231 and history)."""
    if status_code in (302, 303) and method != "HEAD":
        return "GET"
    if status_code == 301 and method == "POST":
        return "GET"
    return method


def _next_hop(
    method: str, kwargs: dict, old_url: str, new_url: str, status_code: int
) -> tuple[str, dict]:
    """Method and options for a redirect hop, rebuilt the way ``requests`` would.

    Following redirects by hand loses everything ``Session.resolve_redirects``
    does, so its rules are reapplied here rather than only the ones that first
    came to mind.
    """
    hop = dict(kwargs)
    # the Location carries its own query; reapplying params can invalidate a
    # signed URL a registry redirects to
    hop.pop("params", None)

    if status_code not in _BODY_PRESERVING_REDIRECTS:
        # a redirected login would otherwise re-send its credentials in the body
        for option in _BODY_OPTIONS:
            hop.pop(option, None)
        hop["headers"] = {
            name: value
            for name, value in (hop.get("headers") or {}).items()
            if name.lower() not in _BODY_HEADERS
        }
        method = _rebuilt_method(method, status_code)

    # borrowed rather than restated: the port and scheme cases are subtle, and a
    # hop that keeps credentials hands the registry token to an unrelated host.
    # `should_strip_auth` ignores `self`, but calling it off a live session reads
    # better than passing None.
    with requests.Session() as redirect_rules:
        if not redirect_rules.should_strip_auth(old_url, new_url):
            return method, hop

    hop.pop("auth", None)
    hop["headers"] = {
        name: value
        for name, value in (hop.get("headers") or {}).items()
        if name.lower() != "authorization"
    }
    return method, hop


class RegistryAdapter(ABC):
    """Abstract base class for registry adapters."""

    def __init__(
        self,
        registry_url: str,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self.registry_url = registry_url
        self.username = username
        self._password = password
        self._token = token
        self.verify_ssl = verify_ssl
        self._allowed_private_networks = _parse_allowed_private_networks(
            os.environ.get(ALLOWED_PRIVATE_NETWORKS_ENV)
        )
        if self._allowed_private_networks:
            logger.warning(
                f"{ALLOWED_PRIVATE_NETWORKS_ENV} is set — SSRF protection relaxed for private networks: "
                + ", ".join(str(net) for net in self._allowed_private_networks)
            )

    @property
    def password(self) -> str | None:
        return self._password

    @property
    def token(self) -> str | None:
        return self._token

    def __getstate__(self) -> dict:
        state = self.__dict__.copy()
        state["_password"] = "***" if state.get("_password") else None
        state["_token"] = "***" if state.get("_token") else None
        return state

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"registry_url={self.registry_url!r}, "
            f"username={self.username!r}, "
            f"password={'<redacted>' if self._password else None}, "
            f"token={'<redacted>' if self._token else None})"
        )

    @abstractmethod
    def list_repositories(self) -> list[str]:
        """Enumerate all repository names in the registry."""
        ...

    @abstractmethod
    def list_tags(self, repository: str) -> list[str]:
        """Enumerate all tags for a repository."""
        ...

    def is_container_image(self, repository: str, tag: str) -> bool:
        """Whether repository:tag points to a scannable container image.

        Registries that store arbitrary OCI artifacts (Helm charts, cosign
        signatures, SBOMs...) override this; by default everything is assumed
        to be an image.
        """
        del repository, tag  # the default inspects neither
        return True

    def _origin_url(self) -> str:
        """The URL whose host the validator compares against when enforce_origin=True.

        Subclasses can override if the effective registry origin differs from
        ``registry_url`` (e.g., Docker Hub talks to ``registry-1.docker.io``).
        """
        return self.registry_url

    def _ip_is_allowed(self, ip_str: str) -> bool:
        """Whether ip_str falls inside an operator-allowlisted private network."""
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        return any(
            addr.version == network.version and addr in network
            for network in self._allowed_private_networks
        )

    def _host_in_allowed_networks(self, host: str) -> bool:
        """Whether host is a literal allowlisted IP or resolves only to allowlisted IPs."""
        try:
            ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                return False
            ips = {sockaddr[0] for *_, sockaddr in infos}
            return bool(ips) and all(self._ip_is_allowed(ip) for ip in ips)
        return self._ip_is_allowed(host)

    def _validate_outbound_url(
        self,
        url: str,
        *,
        enforce_origin: bool = True,
        origin_url: str | None = None,
    ) -> str:
        """Validate a URL before it is passed to ``requests``.

        Defenses against parser-mismatch SSRF (PRWLRHELP-2103):
        - canonicalise via ``requests.PreparedRequest`` so validator and connector
          parse the same string the same way;
        - reject schemes other than http/https;
        - reject literal non-public IPs (private, loopback, link-local, ...)
          unless inside PROWLER_IMAGE_PROVIDER_ALLOWED_PRIVATE_NETWORKS;
        - reject hostnames whose A/AAAA records resolve to non-public IPs,
          with the same allowlist exception;
        - when ``enforce_origin=True``, reject hosts that don't share the
          registry's registrable domain or resolve into the allowlist.

        Returns the canonical URL the caller should pass to ``requests``.
        """
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ImageRegistryAuthError(
                file=__file__,
                message=(
                    f"Disallowed URL scheme: {parsed.scheme!r}. Only http/https are allowed."
                ),
            )

        try:
            prepared = requests.Request("GET", url).prepare()
        except (
            requests.exceptions.InvalidURL,
            requests.exceptions.MissingSchema,
            ValueError,
        ) as exc:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Malformed URL {url!r}: {exc}",
            )

        canonical_url = prepared.url
        canonical = urlparse(canonical_url)
        host = canonical.hostname or ""
        if not host:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"URL has no host: {canonical_url}",
            )

        # Only the address classification is skipped. The origin rule below still
        # applies: a registry-supplied URL pointing at an unrelated host is a
        # different problem from deliberately reaching a private network.
        if not _outbound_check_skipped():
            try:
                ipaddress.ip_address(host)
            except ValueError:
                try:
                    infos = socket.getaddrinfo(host, None)
                except socket.gaierror:
                    infos = []
                for *_, sockaddr in infos:
                    resolved_ip = sockaddr[0]
                    if _ip_is_non_public(resolved_ip) and not self._ip_is_allowed(
                        resolved_ip
                    ):
                        raise ImageRegistryAuthError(
                            file=__file__,
                            message=(
                                f"Host {host!r} resolves to non-public address "
                                f"{resolved_ip}. {_ALLOWLIST_HINT}"
                            ),
                        )
            else:
                if _ip_is_non_public(host) and not self._ip_is_allowed(host):
                    raise ImageRegistryAuthError(
                        file=__file__,
                        message=(
                            f"URL targets a non-public address: {host}. "
                            f"{_ALLOWLIST_HINT}"
                        ),
                    )

        if enforce_origin:
            registry_host = urlparse(origin_url or self._origin_url()).hostname or ""
            if registry_host and host != registry_host:
                target_d = _registrable_domain(host)
                registry_d = _registrable_domain(registry_host)
                same_domain = bool(target_d and registry_d and target_d == registry_d)
                # Non-public TLDs (.local, .internal, bare hostnames) have no
                # registrable domain; fall back to the operator allowlist.
                if not same_domain and not self._host_in_allowed_networks(host):
                    raise ImageRegistryAuthError(
                        file=__file__,
                        message=(
                            f"URL host {host!r} is unrelated to registry host "
                            f"{registry_host!r}; refusing to follow."
                        ),
                    )

        return canonical_url

    def _request_following_validated_redirects(
        self, method: str, url: str, **kwargs
    ) -> requests.Response:
        """Issue a request, validating the destination of each redirect it takes.

        ``requests`` follows redirects itself, which would send the request to a
        host the guard never saw.
        """
        hop_kwargs = dict(kwargs)
        for _ in range(_MAX_REDIRECTS + 1):
            resp = requests.request(method, url, allow_redirects=False, **hop_kwargs)
            if resp.status_code not in _REDIRECT_STATUSES:
                return resp
            location = resp.headers.get("Location")
            if not location:
                return resp
            target = self._validate_outbound_url(
                urljoin(url, location), enforce_origin=False
            )
            method, hop_kwargs = _next_hop(
                method, hop_kwargs, url, target, resp.status_code
            )
            url = target
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"More than {_MAX_REDIRECTS} redirects from {url}.",
        )

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        context_label = kwargs.pop("context_label", None) or self.registry_url
        # the only chokepoint every outbound URL passes through, including the
        # tenant-supplied registry URL that no caller validates
        url = self._validate_outbound_url(url, enforce_origin=False)
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", self.verify_ssl)
        headers = kwargs.get("headers", {})
        headers.setdefault("User-Agent", _USER_AGENT)
        kwargs["headers"] = headers
        last_exception = None
        last_status = None
        last_body = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = self._request_following_validated_redirects(
                    method, url, **kwargs
                )
                if resp.status_code == 429:
                    last_status = 429
                    wait = _BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        f"Rate limited by {context_label}, retrying in {wait}s (attempt {attempt}/{_MAX_RETRIES})"
                    )
                    time.sleep(wait)
                    continue
                if resp.status_code >= 500:
                    last_status = resp.status_code
                    last_body = (resp.text or "")[:500]
                    wait = _BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        f"Server error from {context_label} (HTTP {resp.status_code}), "
                        f"retrying in {wait}s (attempt {attempt}/{_MAX_RETRIES}): {last_body}"
                    )
                    time.sleep(wait)
                    continue
                return resp
            except requests.exceptions.ConnectionError as exc:
                last_exception = exc
                if attempt < _MAX_RETRIES:
                    wait = _BACKOFF_BASE * (2 ** (attempt - 1))
                    logger.warning(
                        f"Connection error to {context_label}, retrying in {wait}s (attempt {attempt}/{_MAX_RETRIES})"
                    )
                    time.sleep(wait)
                    continue
            except requests.exceptions.Timeout as exc:
                raise ImageRegistryNetworkError(
                    file=__file__,
                    message=f"Connection timed out to {context_label}.",
                    original_exception=exc,
                )
        if last_status == 429:
            raise ImageRegistryNetworkError(
                file=__file__,
                message=f"Rate limited by {context_label} after {_MAX_RETRIES} attempts.",
            )
        if last_status is not None and last_status >= 500:
            raise ImageRegistryNetworkError(
                file=__file__,
                message=f"Server error from {context_label} (HTTP {last_status}) after {_MAX_RETRIES} attempts: {last_body}",
            )
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"Failed to connect to {context_label} after {_MAX_RETRIES} attempts.",
            original_exception=last_exception,
        )

    def _next_page_url(self, resp: requests.Response) -> str | None:
        link_header = resp.headers.get("Link", "")
        if not link_header:
            return None
        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if not match:
            return None
        url = match.group(1)
        if url.startswith("/"):
            parsed = urlparse(resp.url)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"
        return self._validate_outbound_url(url)
