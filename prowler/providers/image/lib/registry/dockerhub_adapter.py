"""Docker Hub registry adapter."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from prowler.lib.logger import logger
from prowler.providers.image.exceptions.exceptions import (
    ImageRegistryAuthError,
    ImageRegistryCatalogError,
    ImageRegistryNetworkError,
)
from prowler.providers.image.lib.registry.base import RegistryAdapter

if TYPE_CHECKING:
    import requests

_HUB_API = "https://hub.docker.com"
_REGISTRY_HOST = "https://registry-1.docker.io"
_AUTH_URL = "https://auth.docker.io/token"


class DockerHubAdapter(RegistryAdapter):
    """Adapter for Docker Hub using the Hub REST API + OCI tag listing."""

    def __init__(
        self,
        registry_url: str,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        if not verify_ssl:
            logger.warning(
                "Docker Hub always uses TLS verification; --registry-insecure is ignored for Docker Hub registries."
            )
        super().__init__(registry_url, username, password, token, verify_ssl=True)
        self.namespace = self._extract_namespace(registry_url)
        self._hub_jwt: str | None = None
        self._registry_tokens: dict[str, str] = {}

    @staticmethod
    def _extract_namespace(registry_url: str) -> str:
        url = registry_url.rstrip("/")
        for prefix in (
            "https://registry-1.docker.io",
            "http://registry-1.docker.io",
            "https://docker.io",
            "http://docker.io",
            "registry-1.docker.io",
            "docker.io",
            "https://",
            "http://",
        ):
            if url.startswith(prefix):
                url = url[len(prefix) :]
                break
        url = url.lstrip("/")
        parts = url.split("/")
        namespace = parts[0] if parts and parts[0] else ""
        return namespace

    def list_repositories(self) -> list[str]:
        if not self.namespace:
            raise ImageRegistryCatalogError(
                file=__file__,
                message="Docker Hub requires a namespace. Use --registry docker.io/{org_or_user}.",
            )
        self._hub_login()
        repositories: list[str] = []
        if self._hub_jwt:
            url = f"{_HUB_API}/v2/namespaces/{self.namespace}/repositories"
        else:
            url = f"{_HUB_API}/v2/repositories/{self.namespace}/"
        params: dict = {"page_size": 100}
        while url:
            resp = self._hub_request("GET", url, params=params)
            self._check_hub_response(resp, "repository listing")
            data = resp.json()
            for repo in data.get("results", []):
                name = repo.get("name", "")
                if name:
                    repositories.append(f"{self.namespace}/{name}")
            url = data.get("next")
            params = {}
        return repositories

    def list_tags(self, repository: str) -> list[str]:
        token = self._get_registry_token(repository)
        tags: list[str] = []
        url = f"{_REGISTRY_HOST}/v2/{repository}/tags/list"
        params: dict = {"n": 100}
        while url:
            resp = self._registry_request("GET", url, token, params=params)
            if resp.status_code in (401, 403):
                raise ImageRegistryAuthError(
                    file=__file__,
                    message=f"Authentication failed for tag listing of {repository} on Docker Hub. Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
                )
            if resp.status_code != 200:
                logger.warning(
                    f"Failed to list tags for {repository} (HTTP {resp.status_code}): {resp.text[:200]}"
                )
                break
            data = resp.json()
            tags.extend(data.get("tags", []) or [])
            url = self._next_tag_page_url(resp)
            params = {}
        return tags

    def _hub_login(self) -> None:
        if self._hub_jwt:
            return
        if not self.username or not self.password:
            return
        logger.debug(f"Docker Hub login attempt for username: {self.username!r}")
        resp = self._request_with_retry(
            "POST",
            f"{_HUB_API}/v2/users/login",
            json={"username": self.username, "password": self.password},
            context_label="Docker Hub",
        )
        if resp.status_code != 200:
            body_preview = resp.text[:200] if resp.text else "(empty body)"
            raise ImageRegistryAuthError(
                file=__file__,
                message=(
                    f"Docker Hub login failed (HTTP {resp.status_code}). "
                    f"Check REGISTRY_USERNAME and REGISTRY_PASSWORD. "
                    f"Response: {body_preview}"
                ),
            )
        self._hub_jwt = resp.json().get("token")
        if not self._hub_jwt:
            raise ImageRegistryAuthError(
                file=__file__,
                message="Docker Hub login returned an empty JWT token. Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )

    def _get_registry_token(self, repository: str) -> str:
        if repository in self._registry_tokens:
            return self._registry_tokens[repository]
        params = {
            "service": "registry.docker.io",
            "scope": f"repository:{repository}:pull",
        }
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        resp = self._request_with_retry(
            "GET",
            _AUTH_URL,
            params=params,
            auth=auth,
            context_label="Docker Hub",
        )
        if resp.status_code != 200:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Failed to obtain Docker Hub registry token for {repository} (HTTP {resp.status_code}). Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )
        token = resp.json().get("token", "")
        if not token:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Docker Hub registry token endpoint returned an empty token for {repository}. Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )
        self._registry_tokens[repository] = token
        return token

    def _hub_request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if self._hub_jwt:
            headers["Authorization"] = f"Bearer {self._hub_jwt}"
        kwargs["headers"] = headers
        return self._request_with_retry(
            method, url, context_label="Docker Hub", **kwargs
        )

    def _registry_request(
        self, method: str, url: str, token: str, **kwargs
    ) -> requests.Response:
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {token}"
        kwargs["headers"] = headers
        return self._request_with_retry(
            method, url, context_label="Docker Hub", **kwargs
        )

    def _check_hub_response(self, resp: requests.Response, context: str) -> None:
        if resp.status_code == 200:
            return
        if resp.status_code in (401, 403):
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Authentication failed for {context} on Docker Hub (HTTP {resp.status_code}). Check REGISTRY_USERNAME and REGISTRY_PASSWORD environment variables.",
            )
        if resp.status_code == 404:
            raise ImageRegistryCatalogError(
                file=__file__,
                message=f"Namespace '{self.namespace}' not found on Docker Hub. Check the namespace in --registry docker.io/{{namespace}}.",
            )
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"Unexpected error during {context} on Docker Hub (HTTP {resp.status_code}): {resp.text[:200]}",
        )

    @staticmethod
    def _next_tag_page_url(resp: requests.Response) -> str | None:
        link_header = resp.headers.get("Link", "")
        if not link_header:
            return None
        match = re.search(r'<([^>]+)>;\s*rel="next"', link_header)
        if match:
            next_url = match.group(1)
            if next_url.startswith("/"):
                return f"{_REGISTRY_HOST}{next_url}"
            return next_url
        return None
