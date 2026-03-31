import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from prowler.lib.logger import logger
from prowler.providers.vercel.exceptions.exceptions import (
    VercelAPIError,
    VercelRateLimitError,
)

MAX_WORKERS = 10


class VercelService:
    """Base class for Vercel services to share provider context and HTTP client."""

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        # Set up HTTP session with Bearer token
        self._http_session = requests.Session()
        self._http_session.headers.update(
            {
                "Authorization": f"Bearer {provider.session.token}",
                "Content-Type": "application/json",
            }
        )
        self._base_url = provider.session.base_url
        self._team_id = provider.session.team_id

        # Thread pool for parallel API calls
        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    @property
    def _all_team_ids(self) -> list[str]:
        """Return team IDs to scan: explicit team_id, or all auto-discovered teams."""
        if self._team_id:
            return [self._team_id]
        return [t.id for t in self.provider.identity.teams]

    def _get(self, path: str, params: dict = None) -> dict:
        """Make a rate-limit-aware GET request to the Vercel API.

        Args:
            path: API path (e.g., "/v9/projects").
            params: Query parameters.

        Returns:
            Parsed JSON response as dict.

        Raises:
            VercelRateLimitError: If rate limited after retries.
            VercelAPIError: If the API returns an error.
        """
        if params is None:
            params = {}

        # Append teamId if operating in team scope
        if self._team_id and "teamId" not in params:
            params["teamId"] = self._team_id

        url = f"{self._base_url}{path}"
        max_retries = self.audit_config.get("max_retries", 3)

        for attempt in range(max_retries + 1):
            try:
                response = self._http_session.get(url, params=params, timeout=30)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    if attempt < max_retries:
                        logger.warning(
                            f"{self.service} - Rate limited, retrying after {retry_after}s (attempt {attempt + 1}/{max_retries})"
                        )
                        time.sleep(retry_after)
                        continue
                    raise VercelRateLimitError(
                        file=__file__,
                        message=f"Rate limited on {path} after {max_retries} retries.",
                    )

                if response.status_code == 403:
                    # Plan limitation or permission error — return None for graceful handling
                    logger.warning(
                        f"{self.service} - Access denied for {path} (403). "
                        "This may be a plan limitation."
                    )
                    return None

                response.raise_for_status()
                return response.json()

            except VercelRateLimitError:
                raise
            except requests.exceptions.HTTPError as error:
                raise VercelAPIError(
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
                raise VercelAPIError(
                    file=__file__,
                    original_exception=error,
                    message=f"Request failed on {path} after {max_retries} retries: {error}",
                )

        return {}

    def _paginate(self, path: str, key: str, params: dict = None) -> list:
        """Paginate through a Vercel API list endpoint.

        Vercel uses cursor-based pagination with a `pagination.next` field.

        Args:
            path: API path.
            key: JSON key containing the list of items.
            params: Additional query parameters.

        Returns:
            Combined list of all items across pages.
        """
        if params is None:
            params = {}

        params["limit"] = params.get("limit", 100)
        all_items = []

        while True:
            data = self._get(path, params)
            if data is None:
                break

            items = data.get(key, [])
            all_items.extend(items)

            # Check for next page cursor
            pagination = data.get("pagination", {})
            next_cursor = pagination.get("next")
            if not next_cursor:
                break

            params["until"] = next_cursor

        return all_items

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
