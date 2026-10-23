import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parsedate_to_datetime
from math import isfinite
from typing import Callable, Iterable

import requests
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAPIError,
    SupabaseAuthenticationError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
)

MAX_RATE_LIMIT_DELAY = 3600
MAX_WORKERS = 10
MIN_UNIX_TIMESTAMP = 1_000_000_000
RATE_LIMIT_RETRIES_EXHAUSTED_MESSAGE = (
    "Supabase API rate limit remained active after retries."
)
API_REQUEST_RETRIES_EXHAUSTED_MESSAGE = (
    "Supabase Management API request failed after retries."
)
SUPABASE_API_REQUEST_RETRY_WARNING = (
    "Supabase API request failed; retrying in {delay} seconds."
)


def _bounded_delay(seconds: float) -> int:
    """Return a non-negative, bounded delay in whole seconds."""
    if not isfinite(seconds):
        raise ValueError("Rate-limit delay must be finite.")
    return int(max(0, min(seconds, MAX_RATE_LIMIT_DELAY)))


def _rate_limit_delay(headers: dict) -> int:
    """Return the server-requested rate-limit delay in seconds."""
    reset = headers.get("X-RateLimit-Reset")
    if reset is not None:
        try:
            reset_seconds = float(reset)
            if reset_seconds >= MIN_UNIX_TIMESTAMP:
                reset_seconds -= time.time()
            return _bounded_delay(reset_seconds)
        except (TypeError, ValueError):
            pass

    retry_after = headers.get("Retry-After")
    if retry_after is not None:
        try:
            return _bounded_delay(float(retry_after))
        except (TypeError, ValueError):
            try:
                retry_at = parsedate_to_datetime(retry_after)
                return _bounded_delay(retry_at.timestamp() - time.time())
            except (TypeError, ValueError, OverflowError, OSError):
                pass

    return 1


def request_json(session, path: str, max_retries: int = 3):
    """Make a Management API GET request with explicit authorization errors."""
    url = f"{session.base_url}{path}"
    for attempt in range(max_retries + 1):
        try:
            response = session.http_session.get(url, timeout=30)
            if response.status_code == 401:
                raise SupabaseAuthenticationError(
                    file=__file__,
                    message="Invalid or expired Supabase access token.",
                )
            if response.status_code == 403:
                raise SupabaseInsufficientPermissionsError(
                    file=__file__,
                    message=(
                        "The Supabase access token cannot read the requested "
                        "organization data."
                    ),
                )
            if response.status_code == 429:
                delay = _rate_limit_delay(response.headers)
                if attempt < max_retries:
                    logger.warning(
                        "Supabase API rate limit reached; "
                        f"retrying in {delay} seconds."
                    )
                    time.sleep(delay)
                    continue
                raise SupabaseRateLimitError(
                    file=__file__,
                    message=RATE_LIMIT_RETRIES_EXHAUSTED_MESSAGE,
                )

            response.raise_for_status()
            return response.json()
        except (
            SupabaseAuthenticationError,
            SupabaseInsufficientPermissionsError,
            SupabaseRateLimitError,
        ):
            raise
        except (requests.exceptions.RequestException, ValueError) as error:
            if attempt < max_retries:
                delay = 2**attempt
                msg = SUPABASE_API_REQUEST_RETRY_WARNING.format(delay=delay)
                logger.warning(msg)
                time.sleep(delay)
                continue
            raise SupabaseAPIError(
                file=__file__,
                original_exception=error,
                message=API_REQUEST_RETRIES_EXHAUSTED_MESSAGE,
            )


class SupabaseProjectScope(BaseModel):
    """Project identity shared by every project-level Supabase resource."""

    id: str
    name: str
    project_ref: str
    project_name: str
    organization_slug: str
    organization_name: str
    region: str = ""
    status: str = ""


class SupabaseService:
    """Base class for Supabase services."""

    def __init__(self, service: str, provider):
        self.provider = provider
        self.session = provider.session
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower()

    def _get(self, path: str):
        """Return decoded JSON from a Management API endpoint."""
        return request_json(
            self.session,
            path,
            max_retries=self.audit_config.get("max_retries", 3),
        )

    def _get_optional(self, path: str, label: str):
        """Return decoded JSON, or ``None`` when the endpoint is unavailable.

        Authentication, permission and rate-limit errors still propagate so a
        scan never silently reports an empty estate; any other API failure
        (paused project, feature not provisioned, transient error) is logged
        and the attribute is left unknown.
        """
        try:
            return self._get(path)
        except (
            SupabaseAuthenticationError,
            SupabaseInsufficientPermissionsError,
            SupabaseRateLimitError,
        ):
            raise
        except SupabaseAPIError as error:
            logger.warning(f"{self.service} - {label} unavailable at {path}: {error}")
            return None

    def _list_projects(self) -> list[SupabaseProjectScope]:
        """List projects in scope, honouring the ``--project`` filter."""
        filter_projects = set(getattr(self.provider, "filter_projects", []) or [])
        projects = []
        for raw in self._get("/v1/projects") or []:
            ref = raw.get("ref") or raw.get("id") or ""
            name = raw.get("name", "")
            if not ref:
                continue
            if (
                filter_projects
                and ref not in filter_projects
                and name not in filter_projects
            ):
                continue
            organization_slug = raw.get("organization_slug") or raw.get(
                "organization_id", ""
            )
            projects.append(
                SupabaseProjectScope(
                    id=ref,
                    name=name,
                    project_ref=ref,
                    project_name=name,
                    organization_slug=organization_slug,
                    organization_name=self.provider.identity.organization_name(
                        organization_slug
                    ),
                    region=raw.get("region", "") or "",
                    status=raw.get("status", "") or "",
                )
            )
        logger.info(f"{self.service} - Found {len(projects)} project(s)")
        return projects

    def _threading_call(self, call: Callable, items: Iterable) -> None:
        """Run ``call`` for every item on a bounded thread pool."""
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(call, item): item for item in items}
            for future in as_completed(futures):
                future.result()
