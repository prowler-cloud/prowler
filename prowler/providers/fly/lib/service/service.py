import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from prowler.lib.logger import logger
from prowler.providers.fly.exceptions.exceptions import FlyAPIError, FlyRateLimitError

MAX_WORKERS = 10


class FlyService:
    """Base class for Fly.io services sharing provider context and HTTP client.

    Exposes read-only helpers for the Machines API (``_get``) and the Fly.io
    GraphQL API (``_graphql``). No mutating endpoint is ever called, which keeps
    the provider usable with an organization-scoped read-only token.
    """

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        self._http_session = provider.session.http_session
        if self._http_session is None:
            self._http_session = requests.Session()
            self._http_session.headers.update(
                {
                    "Authorization": f"Bearer {provider.session.token}",
                    "Content-Type": "application/json",
                }
            )
        self._base_url = provider.session.machines_base_url
        self._graphql_url = provider.session.graphql_url

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @property
    def org_slugs(self) -> list[str]:
        """Organization slugs in scope for this scan."""
        return self.provider.identity.org_slugs

    def _is_app_in_scope(self, app_name: str) -> bool:
        """Apply the --app filter, when provided."""
        filter_apps = getattr(self.provider, "filter_apps", None)
        return not filter_apps or app_name in filter_apps

    def _app_scope(self) -> list[tuple[str, str]]:
        """Return the (org_slug, app_name) pairs in scope for the scan.

        Returns:
            list[tuple[str, str]]: In-scope organization and app name pairs.
        """
        scope = []
        try:
            for org_slug in self.org_slugs:
                response = self._get("/apps", params={"org_slug": org_slug})
                if not response:
                    continue
                for app in response.get("apps", []) or []:
                    name = app.get("name")
                    if name and self._is_app_in_scope(name):
                        scope.append((org_slug, name))
        except Exception as error:
            logger.error(
                f"{self.service} - Error listing apps: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return scope

    def _get(self, path: str, params: dict = None):
        """Make a rate-limit-aware GET request to the Fly.io Machines API.

        Args:
            path: API path (e.g., "/apps/my-app/machines").
            params: Query parameters.

        Returns:
            Parsed JSON response, or None when the endpoint is not accessible.

        Raises:
            FlyRateLimitError: If rate limited after retries.
            FlyAPIError: If the API returns an error.
        """
        url = f"{self._base_url}{path}"
        max_retries = self.audit_config.get("max_retries", 3)

        for attempt in range(max_retries + 1):
            try:
                response = self._http_session.get(url, params=params or {}, timeout=30)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    if attempt < max_retries:
                        logger.warning(
                            f"{self.service} - Rate limited, retrying after {retry_after}s (attempt {attempt + 1}/{max_retries})"
                        )
                        time.sleep(retry_after)
                        continue
                    raise FlyRateLimitError(
                        file=__file__,
                        message=f"Rate limited on {path} after {max_retries} retries.",
                    )

                if response.status_code in (403, 404):
                    # The token cannot read this resource; checks handle the gap
                    # explicitly instead of reporting a false PASS.
                    logger.info(
                        f"{self.service} - {path} returned {response.status_code}; "
                        "the token may lack permissions for this resource."
                    )
                    return None

                response.raise_for_status()
                return response.json()

            except FlyRateLimitError:
                raise
            except requests.exceptions.HTTPError as error:
                raise FlyAPIError(
                    file=__file__,
                    original_exception=error,
                    message=f"HTTP error on {path}: {error}",
                )
            except requests.exceptions.RequestException as error:
                if attempt < max_retries:
                    logger.warning(
                        f"{self.service} - Request error on {path}, retrying (attempt {attempt + 1}/{max_retries}): {error}"
                    )
                    time.sleep(2**attempt)
                    continue
                raise FlyAPIError(
                    file=__file__,
                    original_exception=error,
                    message=f"Request failed on {path} after {max_retries} retries: {error}",
                )

        return None

    def _graphql(self, query: str, variables: dict = None) -> dict:
        """Run a read-only query against the Fly.io GraphQL API.

        Args:
            query: The GraphQL query document.
            variables: Query variables.

        Returns:
            The ``data`` object of the response.

        Raises:
            FlyAPIError: If the API or the query fails.
        """
        try:
            response = self._http_session.post(
                self._graphql_url,
                json={"query": query, "variables": variables or {}},
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as error:
            raise FlyAPIError(
                file=__file__,
                original_exception=error,
                message=f"Fly.io GraphQL request failed: {error}",
            )

        if payload.get("errors"):
            raise FlyAPIError(
                file=__file__,
                message=f"Fly.io GraphQL error: {payload['errors']}",
            )

        return payload.get("data", {}) or {}

    def __threading_call__(self, call, iterator):
        """Execute a function across multiple items using threading."""
        items = list(iterator) if not isinstance(iterator, list) else iterator

        futures = {self.thread_pool.submit(call, item): item for item in items}
        results = []

        for future in as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    results.append(result)
            except Exception as error:
                item = futures[future]
                item_id = getattr(item, "id", str(item))
                logger.error(
                    f"{self.service} - Threading error processing {item_id}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )

        return results
