"""Registry adapter abstract base class."""

from __future__ import annotations

from abc import ABC, abstractmethod


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
