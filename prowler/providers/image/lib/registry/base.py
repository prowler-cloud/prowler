"""Registry adapter abstract base class."""

from __future__ import annotations

import re
import time
from abc import ABC, abstractmethod

import requests

from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryNetworkError,
)

_MAX_RETRIES = 3
_BACKOFF_BASE = 1


class RegistryAdapter(ABC):
    """Abstract base class for registry adapters."""

    def __init__(
        self, registry_url, username=None, password=None, token=None, verify_ssl=True
    ):
        self.registry_url = registry_url
        self.username = username
        self.password = password
        self.token = token
        self.verify_ssl = verify_ssl

    @abstractmethod
    def list_repositories(self) -> list[str]:
        """Enumerate all repository names in the registry."""
        ...

    @abstractmethod
    def list_tags(self, repository: str) -> list[str]:
        """Enumerate all tags for a repository."""
        ...

    def _request_with_retry(self, method, url, **kwargs):
        context_label = kwargs.pop("context_label", None) or self.registry_url
        kwargs.setdefault("timeout", 30)
        kwargs.setdefault("verify", self.verify_ssl)
        last_exception = None
        for attempt in range(1, _MAX_RETRIES + 1):
            try:
                resp = requests.request(method, url, **kwargs)
                if resp.status_code == 429:
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
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"Failed to connect to {context_label} after {_MAX_RETRIES} attempts.",
            original_exception=last_exception,
        )

    @staticmethod
    def _next_page_url(resp):
        link_header = resp.headers.get("Link", "")
        if not link_header:
            return None
        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if match:
            return match.group(1)
        return None
