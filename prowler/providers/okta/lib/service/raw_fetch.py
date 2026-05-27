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
request build, transport, decode, parse. Callers are expected to
project the JSON onto their own pydantic snapshot.
"""

import json
from typing import Any, Optional

from prowler.lib.logger import logger


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
