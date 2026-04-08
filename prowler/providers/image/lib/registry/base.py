"""Registry adapter abstract base class."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod
from urllib.parse import urlparse

import requests

from prowler.config.config import prowler_version
from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import ImageRegistryNetworkError

_MAX_RETRIES = 3
_BACKOFF_BASE = 1
_USER_AGENT = f"Prowler/{prowler_version} (registry-adapter)"


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

    @staticmethod
    def _next_page_url(resp: requests.Response) -> str | None:
        link_header = resp.headers.get("Link", "")
        if not link_header:
            return None
        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if match:
            url = match.group(1)
            if url.startswith("/"):
                parsed = urlparse(resp.url)
                return f"{parsed.scheme}://{parsed.netloc}{url}"
            return url
        return None
