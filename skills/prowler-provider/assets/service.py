# Example: Service Base Class and Implementation
# Source: prowler/providers/github/lib/service/service.py
# Source: prowler/providers/github/services/repository/repository_service.py

from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger

# ============================================================
# Base Service Class
# ============================================================


class GithubService:
    """
    Base service class for all GitHub services.

    Key patterns:
    1. Receives provider in __init__
    2. Creates API clients in __set_clients__
    3. Stores audit_config and fixer_config for check access
    """

    def __init__(self, service: str, provider: "GithubProvider"):
        self.provider = provider
        self.clients = self.__set_clients__(provider.session)
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config

    def __set_clients__(self, session: "GithubSession") -> list:
        """Create API clients based on authentication type."""
        clients = []
        try:
            # Create client(s) based on session credentials
            # For token auth: single client
            # For GitHub App: multiple clients (one per installation)
            pass
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")
        return clients


# ============================================================
# Service Implementation
# ============================================================


class Repository(GithubService):
    """
    Repository service - fetches and stores repository data.

    Key patterns:
    1. Inherits from GithubService
    2. Fetches all data in __init__ (eager loading)
    3. Stores data in attributes for check access
    4. Defines Pydantic models for data structures
    """

    def __init__(self, provider: "GithubProvider"):
        super().__init__(__class__.__name__, provider)
        # Fetch and store data during initialization
        self.repositories = self._list_repositories()

    def _list_repositories(self) -> dict:
        """List repositories based on provider scoping."""
        logger.info("Repository - Listing Repositories...")
        repos = {}

        try:
            for client in self.clients:
                # Get repos from specified repositories
                for repo_name in self.provider.repositories:
                    repo = client.get_repo(repo_name)
                    self._process_repository(repo, repos)

                # Get repos from specified organizations
                for org_name in self.provider.organizations:
                    org = client.get_organization(org_name)
                    for repo in org.get_repos():
                        self._process_repository(repo, repos)
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")

        return repos

    def _process_repository(self, repo, repos: dict):
        """Process a single repository and add to repos dict."""
        repos[repo.id] = Repo(
            id=repo.id,
            name=repo.name,
            owner=repo.owner.login,
            full_name=repo.full_name,
            private=repo.private,
            archived=repo.archived,
        )


# ============================================================
# Pydantic Models for Service Data
# ============================================================


class Repo(BaseModel):
    """Model for GitHub Repository."""

    id: int
    name: str
    owner: str
    full_name: str
    private: bool
    archived: bool
    secret_scanning_enabled: Optional[bool] = None
    dependabot_enabled: Optional[bool] = None

    class Config:
        # Make model hashable for use as dict key
        frozen = True
