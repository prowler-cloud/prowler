"""Generic OCI Distribution Spec registry adapter."""

from __future__ import annotations

import base64
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


class OciRegistryAdapter(RegistryAdapter):
    """Adapter for registries implementing OCI Distribution Spec."""

    def __init__(
        self,
        registry_url: str,
        username: str | None = None,
        password: str | None = None,
        token: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        super().__init__(registry_url, username, password, token, verify_ssl)
        self._base_url = self._normalise_url(registry_url)
        self._bearer_token: str | None = None
        self._basic_auth_verified = False

    @staticmethod
    def _normalise_url(url: str) -> str:
        url = url.rstrip("/")
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url

    def list_repositories(self) -> list[str]:
        self._ensure_auth()
        repositories: list[str] = []
        url = f"{self._base_url}/v2/_catalog"
        params: dict = {"n": 200}
        while url:
            resp = self._authed_request("GET", url, params=params)
            if resp.status_code == 404:
                raise ImageRegistryCatalogError(
                    file=__file__,
                    message=f"Registry at {self.registry_url} does not support catalog listing (/_catalog returned 404). Use --image or --image-list instead.",
                )
            self._check_response(resp, "catalog listing")
            data = resp.json()
            repositories.extend(data.get("repositories", []))
            url = self._next_page_url(resp)
            params = {}
        return repositories

    def list_tags(self, repository: str) -> list[str]:
        self._ensure_auth(repository=repository)
        tags: list[str] = []
        url = f"{self._base_url}/v2/{repository}/tags/list"
        params: dict = {"n": 200}
        while url:
            resp = self._authed_request("GET", url, params=params)
            self._check_response(resp, f"tag listing for {repository}")
            data = resp.json()
            tags.extend(data.get("tags", []) or [])
            url = self._next_page_url(resp)
            params = {}
        return tags

    def _ensure_auth(self, repository: str | None = None) -> None:
        if self._bearer_token:
            return
        if self._basic_auth_verified:
            return
        if self.token:
            self._bearer_token = self.token
            return
        ping_url = f"{self._base_url}/v2/"
        resp = self._request_with_retry("GET", ping_url)
        if resp.status_code == 200:
            return
        if resp.status_code == 401:
            www_auth = resp.headers.get("Www-Authenticate", "")

            if not www_auth.lower().startswith("bearer"):
                # Basic auth challenge (e.g., AWS ECR)
                if self.username and self.password:
                    self._basic_auth_verified = True
                    return
                raise ImageRegistryAuthError(
                    file=__file__,
                    message=(
                        f"Registry {self.registry_url} requires authentication "
                        f"but no credentials provided. "
                        f"Set REGISTRY_USERNAME and REGISTRY_PASSWORD."
                    ),
                )

            # Bearer token exchange (standard OCI flow)
            self._bearer_token = self._obtain_bearer_token(www_auth, repository)
            return
        if resp.status_code == 403:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Access denied to registry {self.registry_url} (HTTP 403). Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"Unexpected HTTP {resp.status_code} from registry {self.registry_url} during auth check.",
        )

    def _obtain_bearer_token(
        self, www_authenticate: str, repository: str | None = None
    ) -> str:
        match = re.search(r'realm="([^"]+)"', www_authenticate)
        if not match:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Cannot parse token endpoint from registry {self.registry_url}. Www-Authenticate: {www_authenticate[:200]}",
            )
        realm = match.group(1)
        params: dict = {}
        service_match = re.search(r'service="([^"]+)"', www_authenticate)
        if service_match:
            params["service"] = service_match.group(1)
        scope_match = re.search(r'scope="([^"]+)"', www_authenticate)
        if scope_match:
            params["scope"] = scope_match.group(1)
        elif repository:
            params["scope"] = f"repository:{repository}:pull"
        auth = None
        if self.username and self.password:
            auth = (self.username, self.password)
        resp = self._request_with_retry("GET", realm, params=params, auth=auth)
        if resp.status_code != 200:
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Failed to obtain bearer token from {realm} (HTTP {resp.status_code}). Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )
        data = resp.json()
        return data.get("token") or data.get("access_token", "")

    def _resolve_basic_credentials(self) -> tuple[str | None, str | None]:
        """Decode pre-encoded base64 auth tokens (e.g., from aws ecr get-authorization-token).

        Returns (username, password) — decoded if the password is a base64 token
        containing 'username:real_password', otherwise returned as-is.
        """
        try:
            decoded = base64.b64decode(self.password).decode("utf-8")
            if decoded.startswith(f"{self.username}:"):
                return self.username, decoded[len(self.username) + 1 :]
        except Exception:
            logger.debug("Password is not a base64-encoded auth token, using as-is")
        return self.username, self.password

    def _authed_request(self, method: str, url: str, **kwargs) -> requests.Response:
        headers = kwargs.pop("headers", {})
        if self._bearer_token:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        elif self.username and self.password:
            user, pwd = self._resolve_basic_credentials()
            kwargs.setdefault("auth", (user, pwd))
        kwargs["headers"] = headers
        return self._request_with_retry(method, url, **kwargs)

    def _check_response(self, resp: requests.Response, context: str) -> None:
        if resp.status_code == 200:
            return
        if resp.status_code in (401, 403):
            raise ImageRegistryAuthError(
                file=__file__,
                message=f"Authentication failed for {context} on {self.registry_url} (HTTP {resp.status_code}). Check REGISTRY_USERNAME and REGISTRY_PASSWORD.",
            )
        raise ImageRegistryNetworkError(
            file=__file__,
            message=f"Unexpected error during {context} on {self.registry_url} (HTTP {resp.status_code}): {resp.text[:200]}",
        )
