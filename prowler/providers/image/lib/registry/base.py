"""Registry adapter abstract base class."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import requests
import tldextract

from prowler.config.config import prowler_version
from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryAuthError,
    ImageRegistryNetworkError,
)

_MAX_RETRIES = 3
_BACKOFF_BASE = 1
_USER_AGENT = f"Prowler/{prowler_version} (registry-adapter)"

_NON_PUBLIC_IP_PROPERTIES = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_multicast",
    "is_reserved",
    "is_unspecified",
)


def _ip_is_non_public(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(getattr(addr, prop) for prop in _NON_PUBLIC_IP_PROPERTIES)


def _registrable_domain(host: str) -> str | None:
    ext = tldextract.extract(host)
    if not ext.domain or not ext.suffix:
        return None
    return f"{ext.domain}.{ext.suffix}"


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

    def _origin_url(self) -> str:
        """The URL whose host the validator compares against when enforce_origin=True.

        Subclasses can override if the effective registry origin differs from
        ``registry_url`` (e.g., Docker Hub talks to ``registry-1.docker.io``).
        """
        return self.registry_url

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
        - reject literal non-public IPs (private, loopback, link-local, ...);
        - reject hostnames whose A/AAAA records resolve to non-public IPs;
        - when ``enforce_origin=True``, reject hosts that don't share the
          registry's registrable domain.

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

        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, None)
            except socket.gaierror:
                infos = []
            for *_, sockaddr in infos:
                resolved_ip = sockaddr[0]
                if _ip_is_non_public(resolved_ip):
                    raise ImageRegistryAuthError(
                        file=__file__,
                        message=(
                            f"Host {host!r} resolves to non-public address {resolved_ip}. "
                            "This may indicate an SSRF attempt."
                        ),
                    )
        else:
            if any(getattr(addr, prop) for prop in _NON_PUBLIC_IP_PROPERTIES):
                raise ImageRegistryAuthError(
                    file=__file__,
                    message=(
                        f"URL targets a non-public address: {host}. "
                        "This may indicate an SSRF attempt."
                    ),
                )

        if enforce_origin:
            registry_host = urlparse(origin_url or self._origin_url()).hostname or ""
            if registry_host and host != registry_host:
                target_d = _registrable_domain(host)
                registry_d = _registrable_domain(registry_host)
                if not (target_d and registry_d and target_d == registry_d):
                    raise ImageRegistryAuthError(
                        file=__file__,
                        message=(
                            f"URL host {host!r} is unrelated to registry host "
                            f"{registry_host!r}; refusing to follow."
                        ),
                    )

        return canonical_url

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response:
        context_label = kwargs.pop("context_label", None) or self.registry_url
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
                resp = requests.request(method, url, **kwargs)
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
