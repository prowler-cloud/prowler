"""Base service class for Lovable services.

Provides a thin HTTP layer with retry, rate-limit awareness, and the
authenticated session shared across services.
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from prowler.lib.logger import logger
from prowler.providers.lovable.config import (
    LOVABLE_DEFAULT_TIMEOUT,
    LOVABLE_USER_AGENT,
)
from prowler.providers.lovable.exceptions.exceptions import (
    LovableAPIError,
    LovableRateLimitError,
)

MAX_WORKERS = 8


class LovableService:
    """Base class shared by every Lovable service."""

    def __init__(self, service: str, provider):
        self.provider = provider
        self.audit_config = provider.audit_config
        self.fixer_config = provider.fixer_config
        self.service = service.lower() if not service.islower() else service

        self._http_session = requests.Session()
        self._http_session.headers.update(
            {
                "Authorization": f"Bearer {provider.session.api_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": LOVABLE_USER_AGENT,
            }
        )
        self._base_url = provider.session.base_url
        self._workspace_id = provider.session.workspace_id

        self.thread_pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)

    def _get(self, path: str, params: dict | None = None) -> dict | None:
        """GET wrapper with retry and rate-limit handling.

        Returns parsed JSON dict on success, None on auth/scope failures so the
        caller can degrade gracefully.
        """
        params = dict(params or {})
        if self._workspace_id and "workspaceId" not in params:
            params["workspaceId"] = self._workspace_id

        url = f"{self._base_url}{path}"
        max_retries = self.audit_config.get("max_retries", 3)

        for attempt in range(max_retries + 1):
            try:
                response = self._http_session.get(
                    url, params=params, timeout=LOVABLE_DEFAULT_TIMEOUT
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    if attempt < max_retries:
                        logger.warning(
                            f"{self.service} - Rate limited on {path}, "
                            f"retrying after {retry_after}s "
                            f"(attempt {attempt + 1}/{max_retries})"
                        )
                        time.sleep(retry_after)
                        continue
                    raise LovableRateLimitError(
                        file=__file__,
                        message=f"Rate limited on {path} after {max_retries} retries.",
                    )

                if response.status_code in (401, 403):
                    logger.info(
                        f"{self.service} - {response.status_code} on {path}; "
                        "skipping (token may lack scope)."
                    )
                    return None

                if response.status_code == 404:
                    return None

                response.raise_for_status()
                return response.json() if response.content else {}

            except LovableRateLimitError:
                raise
            except requests.exceptions.HTTPError as error:
                raise LovableAPIError(
                    file=__file__,
                    original_exception=error,
                    message=f"HTTP error on {path}: {error}",
                )
            except requests.exceptions.RequestException as error:
                if attempt < max_retries:
                    logger.warning(
                        f"{self.service} - Request error on {path}, retrying "
                        f"(attempt {attempt + 1}/{max_retries}): {error}"
                    )
                    time.sleep(2**attempt)
                    continue
                raise LovableAPIError(
                    file=__file__,
                    original_exception=error,
                    message=f"Request failed on {path} after {max_retries} retries: {error}",
                )

        return None

    def _paginate(self, path: str, key: str, params: dict | None = None) -> list:
        """Simple cursor pagination helper for Lovable list endpoints."""
        params = dict(params or {})
        params.setdefault("limit", 100)

        items: list = []
        cursor = None
        while True:
            if cursor:
                params["cursor"] = cursor
            data = self._get(path, params)
            if not data:
                break
            items.extend(data.get(key, []) or [])
            cursor = (data.get("pagination") or {}).get("next")
            if not cursor:
                break
        return items

    def __threading_call__(self, call, iterator):
        """Run `call` for every item in `iterator` using the shared pool."""
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
                    f"{self.service} - Threading error on {item_id}: "
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return results
