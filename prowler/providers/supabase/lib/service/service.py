import time
from email.utils import parsedate_to_datetime
from math import isfinite

import requests

from prowler.lib.logger import logger
from prowler.providers.supabase.exceptions.exceptions import (
    SupabaseAPIError,
    SupabaseAuthenticationError,
    SupabaseInsufficientPermissionsError,
    SupabaseRateLimitError,
)

MAX_RATE_LIMIT_DELAY = 3600
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
