"""Registry adapter abstract base class."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod

import requests

from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import ImageRegistryNetworkError

_MAX_RETRIES = 3
_BACKOFF_BASE = 1


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
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"registry_url={self.registry_url!r}, "
            f"username={self.username!r}, "
            f"password={'<redacted>' if self.password else None}, "
            f"token={'<redacted>' if self.token else None})"
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
        last_exception = None
        last_status = None
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
            return match.group(1)
        return None
