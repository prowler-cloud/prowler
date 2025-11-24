"""Shared API client utilities for Prowler App tools."""

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
            ValueError: If date range exceeds max_days

        Examples:
            >>> normalize_date_range(None, None)
            None  # Use latest endpoint
            >>> normalize_date_range("2024-01-15", None)
            ("2024-01-15", "2024-01-16")  # Auto-complete to_date
            >>> normalize_date_range(None, "2024-01-16")
            ("2024-01-15", "2024-01-16")  # Auto-complete from_date
        """
        if not date_from and not date_to:
            return None

        # Parse provided dates
        from_date: datetime | None = (
            datetime.strptime(date_from, "%Y-%m-%d") if date_from else None
        )
        to_date: datetime | None = (
            datetime.strptime(date_to, "%Y-%m-%d") if date_to else None
        )

        # Auto-complete missing boundary to maintain max_days window
        if from_date and not to_date:
            to_date = from_date + timedelta(days=max_days - 1)
        elif to_date and not from_date:
            from_date = to_date - timedelta(days=max_days - 1)

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
        """Build filter parameters for API, converting arrays to comma-separated strings.

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

            # Convert lists/arrays to comma-separated strings
            if isinstance(value, (list, tuple)):
                result[key] = ",".join(str(v) for v in value)
            else:
                result[key] = value

        return result
