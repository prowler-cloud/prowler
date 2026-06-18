"""Raw-JSON HTTP fetch via the Okta SDK's request executor.

Some Okta Management API endpoints are not yet exposed as typed methods
on the SDK client (e.g. `/api/v1/automations`), or the typed path's
pydantic deserialization rejects values the API actually returns (e.g.
the `KnowledgeConstraint.types` lowercase issue we hit on
`list_policy_rules`). In both cases we go around the typed layer:
construct the request via `client._request_executor.create_request`,
execute without a response type, and parse the body ourselves.

`get_json` returns the parsed JSON payload (typically a list or dict)
or raises with a descriptive log line on any of the failure modes —
request build, transport, decode, parse. `get_json_paginated` drains
list endpoints by following the `Link: rel="next"` cursor — without it,
the raw fallback would silently truncate at the per-request `limit`.
Callers are expected to project the JSON onto their own pydantic snapshot.
"""

import json
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from prowler.lib.logger import logger
from prowler.providers.okta.lib.service.pagination import next_after_cursor


async def get_json(
    client,
    path: str,
    *,
    accept: str = "application/json",
    context: Optional[str] = None,
) -> Optional[Any]:
    """GET `path` via the SDK's request executor and return parsed JSON.

    Returns the decoded JSON payload on success, or None when the
    request, transport, or decode steps fail. Each failure path emits a
    `logger.error` line tagged with `context` so the caller can grep
    for it.
    """
    label = context or path
    request, error = await client._request_executor.create_request(
        method="GET",
        url=path,
        body=None,
        headers={"Accept": accept},
    )
    if error is not None:
        logger.error(f"Raw fetch (create_request) failed for {label}: {error}")
        return None

    _response, response_body, error = await client._request_executor.execute(request)
    if error is not None:
        logger.error(f"Raw fetch (execute) failed for {label}: {error}")
        return None

    if isinstance(response_body, (bytes, bytearray)):
        try:
            response_body = response_body.decode("utf-8")
        except UnicodeDecodeError as decode_err:
            logger.error(f"Could not decode response for {label}: {decode_err}")
            return None
    try:
        return json.loads(response_body) if response_body else None
    except json.JSONDecodeError as decode_err:
        logger.error(f"Could not parse JSON for {label}: {decode_err}")
        return None


async def get_json_paginated(
    client,
    path: str,
    *,
    page_size: int = 200,
    accept: str = "application/json",
    context: Optional[str] = None,
) -> Optional[list]:
    """Drain all pages of a raw-JSON list endpoint.

    Mirrors the typed `pagination.paginate` shape but operates on the
    SDK's request executor directly. Follows the `Link: rel="next"`
    header until exhausted, accumulating items across pages. Returns
    the concatenated list, or None if any page fails to fetch or the
    response is not a JSON array.

    `page_size` is appended as `limit=N` to the first request; subsequent
    requests use the URL Okta returns via the cursor.
    """
    label = context or path
    all_items: list = []
    current_path = _set_query(path, {"limit": str(page_size)})
    while True:
        request, error = await client._request_executor.create_request(
            method="GET",
            url=current_path,
            body=None,
            headers={"Accept": accept},
        )
        if error is not None:
            logger.error(f"Raw fetch (create_request) failed for {label}: {error}")
            return None

        response, response_body, error = await client._request_executor.execute(request)
        if error is not None:
            logger.error(f"Raw fetch (execute) failed for {label}: {error}")
            return None

        if isinstance(response_body, (bytes, bytearray)):
            try:
                response_body = response_body.decode("utf-8")
            except UnicodeDecodeError as decode_err:
                logger.error(f"Could not decode response for {label}: {decode_err}")
                return None
        if not response_body:
            break
        try:
            page = json.loads(response_body)
        except json.JSONDecodeError as decode_err:
            logger.error(f"Could not parse JSON for {label}: {decode_err}")
            return None
        if not isinstance(page, list):
            logger.error(
                f"Unexpected raw payload shape for {label}: "
                f"{type(page).__name__}; expected list"
            )
            return None
        all_items.extend(page)

        cursor = next_after_cursor(response)
        if not cursor:
            break
        current_path = _set_query(path, {"limit": str(page_size), "after": cursor})
    return all_items


def _set_query(path: str, params: dict) -> str:
    """Return `path` with the given query params merged in (overriding existing)."""
    parsed = urlparse(path)
    qs = dict(parse_qsl(parsed.query))
    qs.update({k: v for k, v in params.items() if v is not None})
    return urlunparse(parsed._replace(query=urlencode(qs)))
