"""Shared API client utilities for Prowler App tools."""

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict

import httpx
from prowler_mcp_server.lib.logger import logger
from prowler_mcp_server.prowler_app.utils.auth import ProwlerAppAuth


class HTTPMethod(str, Enum):
    """HTTP methods enum."""

    GET = "GET"
    POST = "POST"
    PATCH = "PATCH"
    DELETE = "DELETE"


class SingletonMeta(type):
    """Metaclass that implements the Singleton pattern.

    This metaclass ensures that only one instance of a class exists.
    All calls to the constructor return the same instance.
    """

    _instances: Dict[type, Any] = {}

    def __call__(cls, *args, **kwargs):
        """Control instance creation to ensure singleton behavior."""
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class ProwlerAPIClient(metaclass=SingletonMeta):
    """Shared API client with smart defaults and helper methods.

    This class uses the Singleton pattern via metaclass to ensure only one
    instance exists across the application, reducing initialization overhead
    and enabling HTTP connection pooling.
    """

    def __init__(self) -> None:
        """Initialize the API client (only called once due to singleton pattern)."""
        self.auth_manager: ProwlerAppAuth = ProwlerAppAuth()
        self.client: httpx.AsyncClient = httpx.AsyncClient(timeout=30.0)

    async def _make_request(
        self,
        method: HTTPMethod,
        path: str,
        params: dict[str, any] | None = None,
        json_data: dict[str, any] | None = None,
    ) -> dict[str, any]:
        """Make authenticated API request.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            path: API endpoint path
            params: Optional query parameters
            json_data: Optional JSON body data

        Returns:
            API response as dictionary

        Raises:
            Exception: If API request fails
        """
        try:
            token: str = await self.auth_manager.get_valid_token()
            url: str = f"{self.auth_manager.base_url}{path}"
            headers: dict[str, str] = self.auth_manager.get_headers(token)

            response: httpx.Response = await self.client.request(
                method=method.value,
                url=url,
                headers=headers,
                params=params,
                json=json_data,
            )
            response.raise_for_status()

            if not response.content:
                return {
                    "success": True,
                    "status_code": response.status_code,
                }
            else:
                return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error during {method.value} {path}: {e}")
            error_detail: str = ""
            try:
                error_data: dict[str, any] = e.response.json()
                error_detail = error_data.get("errors", [{}])[0].get("detail", "")
            except Exception:
                error_detail = e.response.text

            raise Exception(
                f"API request failed: {e.response.status_code} - {error_detail}"
            )
        except Exception as e:
            logger.error(f"Error during {method.value} {path}: {e}")
            raise

    async def get(
        self, path: str, params: dict[str, any] | None = None
    ) -> dict[str, any]:
        """Make GET request.

        Args:
            path: API endpoint path
            params: Optional query parameters

        Returns:
            API response as dictionary

        Raises:
            Exception: If API request fails
        """
        return await self._make_request(HTTPMethod.GET, path, params=params)

    async def post(
        self,
        path: str,
        params: dict[str, any] | None = None,
        json_data: dict[str, any] | None = None,
    ) -> dict[str, any]:
        """Make POST request.

        Args:
            path: API endpoint path
            params: Optional query parameters
            json_data: Optional JSON body data

        Returns:
            API response as dictionary

        Raises:
            Exception: If API request fails
        """
        return await self._make_request(
            HTTPMethod.POST, path, params=params, json_data=json_data
        )

    async def patch(
        self,
        path: str,
        params: dict[str, any] | None = None,
        json_data: dict[str, any] | None = None,
    ) -> dict[str, any]:
        """Make PATCH request.

        Args:
            path: API endpoint path
            params: Optional query parameters
            json_data: Optional JSON body data

        Returns:
            API response as dictionary

        Raises:
            Exception: If API request fails
        """
        return await self._make_request(
            HTTPMethod.PATCH, path, params=params, json_data=json_data
        )

    async def delete(
        self, path: str, params: dict[str, any] | None = None
    ) -> dict[str, any]:
        """Make DELETE request.

        Args:
            path: API endpoint path
            params: Optional query parameters

        Returns:
            API response as dictionary

        Raises:
            Exception: If API request fails
        """
        return await self._make_request(HTTPMethod.DELETE, path, params=params)

    async def poll_task_until_complete(
        self,
        task_id: str,
        timeout: int = 60,
        poll_interval: float = 1.0,
    ) -> dict[str, any]:
        """Poll a task until it reaches a terminal state.

        This method polls the task endpoint at regular intervals until the task
        completes, fails, or times out. It's designed for async operations like
        provider connection tests and deletions that return task IDs.

        Args:
            task_id: The UUID of the task to poll (UUID object or string)
            timeout: Maximum time to wait in seconds (default: 60)
            poll_interval: Time between polls in seconds (default: 1.0)

        Returns:
            The complete task response when terminal state is reached

        Raises:
            Exception: If task fails, is cancelled, or timeout is exceeded
        """
        terminal_states = {"completed", "failed", "cancelled"}
        start_time = asyncio.get_event_loop().time()
        max_time = start_time + timeout

        logger.info(
            f"Polling task {task_id} (timeout: {timeout}s, interval: {poll_interval}s)"
        )

        while True:
            # Check if we've exceeded the timeout
            current_time = asyncio.get_event_loop().time()
            if current_time >= max_time:
                raise Exception(
                    f"Task {task_id} polling timed out after {timeout} seconds. "
                    f"The task may still be running. Try increasing the timeout or check task status manually."
                )

            # Fetch current task state
            response = await self.get(f"/tasks/{task_id}")
            task_data = response.get("data", {})
            task_attrs = task_data.get("attributes", {})
            state = task_attrs.get("state")

            logger.debug(f"Task {task_id} state: {state}")

            # Check if we've reached a terminal state
            if state in terminal_states:
                if state == "completed":
                    logger.info(f"Task {task_id} completed successfully")
                    return response
                elif state == "failed":
                    error_msg = task_attrs.get("error", "Unknown error")
                    raise Exception(f"Task {task_id} failed: {error_msg}")
                elif state == "cancelled":
                    raise Exception(f"Task {task_id} was cancelled")

            # Wait before next poll
            await asyncio.sleep(poll_interval)

    def _validate_date_format(self, date_str: str, param_name: str) -> datetime:
        """Validate date string format.

        Args:
            date_str: Date string to validate
            param_name: Parameter name for error messages

        Returns:
            Parsed datetime object

        Raises:
            ValueError: If date format is invalid
        """
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            raise ValueError(
                f"Invalid date format for {param_name}. Expected YYYY-MM-DD (e.g., '2025-01-15'), got '{date_str}'. "
                f"Full date required - partial dates like '2025' or '2025-01' are not accepted."
            )

    def validate_page_size(self, page_size: int) -> None:
        """Validate page size parameter.

        Args:
            page_size: Page size to validate

        Raises:
            ValueError: If page size is out of valid range (1-1000)
        """
        if page_size < 1 or page_size > 1000:
            raise ValueError(
                f"Invalid page_size: {page_size}. Must be between 1 and 1000 (inclusive)."
            )

    def normalize_date_range(
        self, date_from: str | None, date_to: str | None, max_days: int = 2
    ) -> tuple[str, str] | None:
        """Normalize and validate date range, auto-completing missing boundary.

        The Prowler API has a 2-day limit for historical queries. This helper:
        1. Returns None if no dates provided (signals: use latest/default endpoint)
        2. Auto-completes missing boundary to maintain 2-day window
        3. Validates the range doesn't exceed max_days

        Args:
            date_from: Start date (YYYY-MM-DD format) or None
            date_to: End date (YYYY-MM-DD format) or None
            max_days: Maximum allowed days between dates (default: 2)

        Returns:
            None if no dates provided, otherwise tuple of (date_from, date_to) as strings

        Raises:
            ValueError: If date range exceeds max_days or date format is invalid
        """
        if not date_from and not date_to:
            return None

        # Parse and validate provided dates
        from_date: datetime | None = (
            self._validate_date_format(date_from, "date_from") if date_from else None
        )
        to_date: datetime | None = (
            self._validate_date_format(date_to, "date_to") if date_to else None
        )

        # Auto-complete missing boundary to maintain max_days window
        if from_date and not to_date:
            to_date = from_date + timedelta(days=max_days - 1)
        elif to_date and not from_date:
            from_date = to_date - timedelta(days=max_days - 1)

        # Validate that date_from is before or equal to date_to
        if from_date > to_date:
            raise ValueError(
                f"Invalid date range: date_from must be before or equal to date_to. "
                f"Got date_from='{from_date.date()}' and date_to='{to_date.date()}'. "
                f"Please swap the dates or use the correct order."
            )

        # Validate range doesn't exceed max_days
        delta: int = (to_date - from_date).days + 1
        if delta > max_days:
            raise ValueError(
                f"Date range cannot exceed {max_days} days. "
                f"Requested range: {from_date.date()} to {to_date.date()} ({delta} days)"
            )

        return from_date.strftime("%Y-%m-%d"), to_date.strftime("%Y-%m-%d")

    def build_filter_params(
        self, params: dict[str, any], exclude_none: bool = True
    ) -> dict[str, any]:
        """Build filter parameters for API, converting types to API-compatible formats.

        Args:
            params: Dictionary of parameters
            exclude_none: If True, exclude None values from result

        Returns:
            Cleaned parameter dictionary ready for API
        """
        result: dict[str, any] = {}
        for key, value in params.items():
            if value is None and exclude_none:
                continue

            # Convert boolean values to lowercase strings for API compatibility
            if isinstance(value, bool):
                result[key] = str(value).lower()
            # Convert lists/arrays to comma-separated strings
            elif isinstance(value, (list, tuple)):
                result[key] = ",".join(str(v) for v in value)
            else:
                result[key] = value

        return result
