import math
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

from prowler.lib.logger import logger
from prowler.providers.fly.exceptions.exceptions import (
    FlyAPIError,
    FlyAuthenticationError,
    FlyRateLimitError,
)

MAX_WORKERS = 10
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_AFTER_SECONDS = 5
# Upper bound for a single Retry-After wait so a far-future HTTP-date cannot
# stall the scan; the request is retried and rate limited again if needed.
MAX_RETRY_AFTER_SECONDS = 300
# Upper bound for the total time one request may spend waiting on rate limits.
MAX_TOTAL_RETRY_WAIT_SECONDS = 600
MAX_RETRIES_LIMIT = 10


def config_value(audit_config, key: str, default):
    """Read a provider configuration key null-safely.

    A missing configuration, a missing key and an explicit ``null`` value all
    resolve to ``default``. An explicit empty list or ``0`` is kept as
    configured, so ``allowed_public_ports: []`` still means "no port allowed".

    Args:
        audit_config: The provider audit configuration, possibly ``None``.
        key: The configuration key to read.
        default: The value used when the key holds no value.

    Returns:
        The configured value or ``default``.
    """
    if not isinstance(audit_config, dict):
        return default
    value = audit_config.get(key)
    return default if value is None else value


def parse_retry_after(
    value, default: int = DEFAULT_RETRY_AFTER_SECONDS, now: datetime = None
) -> int:
    """Parse a ``Retry-After`` header into a number of seconds to wait.

    RFC 9110 allows the header to carry either a delay in seconds or an
    HTTP-date (IMF-fixdate, for example ``Sun, 06 Nov 1994 08:49:37 GMT``).
    Both forms are accepted; an absent, empty or unparsable value falls back to
    ``default`` and a date in the past yields ``0``.

    Args:
        value: The raw header value, or ``None`` when the header is absent.
        default: Seconds to wait when the header cannot be interpreted.
        now: Reference time for HTTP-dates; defaults to the current UTC time.

    Returns:
        int: Seconds to wait, capped at ``MAX_RETRY_AFTER_SECONDS``.
    """
    if value is None:
        return default

    text = str(value).strip()
    if not text:
        return default

    if text.isdecimal():
        return min(int(text), MAX_RETRY_AFTER_SECONDS)

    try:
        retry_at = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return default
    if retry_at is None:
        return default
    if retry_at.tzinfo is None:
        retry_at = retry_at.replace(tzinfo=timezone.utc)

    reference = now or datetime.now(timezone.utc)
    delay = math.ceil((retry_at - reference).total_seconds())
    return min(max(delay, 0), MAX_RETRY_AFTER_SECONDS)


class FlyService:
    """Base class for Fly.io services sharing provider context and HTTP client.

    Exposes read-only helpers for the Machines API (``_get``) and the Fly.io
    GraphQL API (``_graphql``). No mutating endpoint is ever called, which keeps
    the provider usable with an organization-scoped read-only token.
    """

    def __init__(self, service: str, provider):
        """Initialize the shared Fly.io service context.

        Args:
            service: The service name, used as prefix in log messages.
            provider: The Fly.io provider carrying the session and configuration.
        """
        self.provider = provider
        self.audit_config = (
            provider.audit_config if isinstance(provider.audit_config, dict) else {}
        )
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

    @property
    def max_retries(self) -> int:
        """Configured retry budget for Machines API requests, kept in 0..10.

        The schema already bounds ``max_retries`` for configuration files; a
        configuration passed as content bypasses it, so the value is clamped
        here and an invalid value falls back to the default.
        """
        value = config_value(self.audit_config, "max_retries", DEFAULT_MAX_RETRIES)
        try:
            return min(max(int(value), 0), MAX_RETRIES_LIMIT)
        except (TypeError, ValueError):
            logger.warning(
                f"{self.service} - Invalid max_retries value {value!r}; using "
                f"{DEFAULT_MAX_RETRIES}."
            )
            return DEFAULT_MAX_RETRIES

    def _is_app_in_scope(self, app_name: str) -> bool:
        """Apply the --app filter, when provided."""
        filter_apps = getattr(self.provider, "filter_apps", None)
        return not filter_apps or app_name in filter_apps

    def _app_scope(self) -> list[tuple[str, str]]:
        """Return the (org_slug, app_name) pairs in scope for the scan.

        An organization whose apps cannot be listed is logged and skipped so
        the remaining organizations are still scanned.

        Returns:
            list[tuple[str, str]]: In-scope organization and app name pairs.
        """
        scope = []
        for org_slug in self.org_slugs:
            try:
                response = self._get("/apps", params={"org_slug": org_slug})
                if not response:
                    continue
                for app in response.get("apps", []) or []:
                    name = app.get("name")
                    if name and self._is_app_in_scope(name):
                        scope.append((org_slug, name))
            except Exception as error:
                logger.error(
                    f"{self.service} - Error listing apps for organization {org_slug}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return scope

    def _get(self, path: str, params: dict = None):
        """Make a rate-limit-aware GET request to the Fly.io Machines API.

        Authorization failures are never swallowed: a 401 or 403 raises
        ``FlyAuthenticationError``, which every service logs as an error, so a
        resource class can not silently disappear from the scan. A 404 is
        logged as a warning and returns ``None``.

        Args:
            path: API path (e.g., "/apps/my-app/machines").
            params: Query parameters.

        Rate-limit waits honor ``Retry-After`` up to ``MAX_RETRY_AFTER_SECONDS``
        each and ``MAX_TOTAL_RETRY_WAIT_SECONDS`` per request in total.

        Returns:
            Parsed JSON response, or None when the resource does not exist or
            is not visible to the token (404).

        Raises:
            FlyAuthenticationError: If the token is rejected (401) or lacks
                access to the resource (403).
            FlyRateLimitError: If rate limited after retries.
            FlyAPIError: If the API returns any other error.
        """
        url = f"{self._base_url}{path}"
        max_retries = self.max_retries
        waited = 0

        for attempt in range(max_retries + 1):
            try:
                response = self._http_session.get(url, params=params or {}, timeout=30)

                if response.status_code == 429:
                    retry_after = parse_retry_after(response.headers.get("Retry-After"))
                    if (
                        attempt < max_retries
                        and waited + retry_after <= MAX_TOTAL_RETRY_WAIT_SECONDS
                    ):
                        logger.warning(
                            f"{self.service} - Rate limited, retrying after {retry_after}s (attempt {attempt + 1}/{max_retries})"
                        )
                        time.sleep(retry_after)
                        waited += retry_after
                        continue
                    raise FlyRateLimitError(
                        file=__file__,
                        message=(
                            f"Rate limited on {path} after {attempt} retries and "
                            f"{waited}s of waiting."
                        ),
                    )

                if response.status_code == 401:
                    raise FlyAuthenticationError(
                        file=__file__,
                        message=(
                            f"Unauthorized (401) on {path}: the Fly.io token is "
                            "invalid, expired or revoked."
                        ),
                    )

                if response.status_code == 403:
                    raise FlyAuthenticationError(
                        file=__file__,
                        message=(
                            f"Access denied (403) on {path}: the Fly.io token lacks "
                            "read access to this resource, so it is missing from "
                            "the scan results."
                        ),
                    )

                if response.status_code == 404:
                    logger.warning(
                        f"{self.service} - Not found (404) on {path}: the resource "
                        "does not exist or is not visible to the Fly.io token, so it "
                        "is missing from the scan results."
                    )
                    return None

                response.raise_for_status()
                return response.json()

            except (FlyAuthenticationError, FlyRateLimitError):
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

        # Unreachable with a valid retry budget; never let a request vanish quietly.
        raise FlyAPIError(file=__file__, message=f"No response obtained for {path}.")

    def _graphql(self, query: str, variables: dict = None) -> dict:
        """Run a read-only query against the Fly.io GraphQL API.

        Args:
            query: The GraphQL query document.
            variables: Query variables.

        Returns:
            The ``data`` object of the response.

        Raises:
            FlyAuthenticationError: If the token is rejected (401) or lacks
                access (403).
            FlyAPIError: If the API or the query fails.
        """
        try:
            response = self._http_session.post(
                self._graphql_url,
                json={"query": query, "variables": variables or {}},
                timeout=30,
            )
            if response.status_code in (401, 403):
                raise FlyAuthenticationError(
                    file=__file__,
                    message=(
                        f"Fly.io GraphQL API returned {response.status_code}: the "
                        "token is invalid, expired or lacks read access to the "
                        "organization."
                    ),
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
