from __future__ import annotations

import re
from typing import Any

import requests

from prowler.lib.logger import logger
from prowler.providers.e2enetworks.exceptions.exceptions import E2eNetworksAPIError
from prowler.providers.e2enetworks.models import E2eNetworksSession


def _redact_sensitive_values(message: str) -> str:
    """Redact E2E Networks secrets from request error messages."""
    redacted = re.sub(r"(?i)(apikey=)[^&\s]+", r"\1REDACTED", message)
    return re.sub(
        r"(?i)(Authorization:\s*Bearer\s+|Bearer\s+)[^\s,;]+",
        r"\1REDACTED",
        redacted,
    )


class E2eNetworksAPIClient:
    """Shared HTTP client for E2E Networks MyAccount API requests."""

    def __init__(self, session: E2eNetworksSession):
        self.session = session

    def _auth_params(self, location: str, extra: dict | None = None) -> dict[str, Any]:
        params = {
            "apikey": self.session.api_key,
            "project_id": self.session.project_id,
            "location": location,
        }
        if extra:
            params.update(extra)
        return params

    def get(
        self,
        path: str,
        location: str,
        params: dict | None = None,
        timeout: int = 30,
    ) -> dict:
        """Perform a GET request against the E2E Networks API."""
        url = f"{self.session.base_url}{path}"
        query_params = self._auth_params(location, params)
        try:
            response = self.session.http_session.get(
                url,
                params=query_params,
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                return {"data": payload}
            return payload
        except requests.exceptions.RequestException as error:
            redacted_error = _redact_sensitive_values(str(error))
            logger.error(
                f"E2E API GET {path} failed: {error.__class__.__name__}: {redacted_error}"
            )
            raise E2eNetworksAPIError(
                message=f"GET {path} failed for location {location}",
                original_exception=Exception(redacted_error),
            ) from error

    def get_data(
        self,
        path: str,
        location: str,
        params: dict | None = None,
    ) -> list | dict:
        """Return the `data` field from a standard E2E API envelope."""
        payload = self.get(path, location=location, params=params)
        return payload.get("data", [])

    def paginate(
        self,
        path: str,
        location: str,
        params: dict | None = None,
        per_page: int = 100,
    ) -> list:
        """Iterate page_no/per_page style paginated list endpoints."""
        all_items: list = []
        page_no = 1
        total_pages = 1

        while page_no <= total_pages:
            page_params = {"page_no": page_no, "per_page": per_page}
            if params:
                page_params.update(params)

            payload = self.get(path, location=location, params=page_params)
            data = payload.get("data", [])
            if isinstance(data, list):
                all_items.extend(data)
            elif isinstance(data, dict):
                all_items.extend(data.values())

            total_pages = int(payload.get("total_page_number", page_no))
            if not data:
                break
            page_no += 1

        return all_items
