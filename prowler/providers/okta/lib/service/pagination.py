"""Shared pagination helpers for Okta SDK list calls.

The Okta SDK exposes paginated list endpoints (`list_applications`,
`list_policies`, `list_log_streams`, `list_identity_providers`, …) that
return a tuple `(items, response, error)`. The next page is signalled
through an RFC 5988 `Link: <…>; rel="next"` header carrying an opaque
`after` cursor.

These helpers are used by every Okta service that needs to drain a
paginated endpoint. They live here so we don't keep copy-pasting them
into each service module.
"""

from typing import Optional
from urllib.parse import parse_qs, urlparse


def next_after_cursor(resp) -> Optional[str]:
    """Extract the `after` cursor from a `Link: ...; rel="next"` header.

    Returns None when there is no next page. Header format follows RFC
    5988 and Okta's pagination guide.
    """
    if resp is None:
        return None
    headers = getattr(resp, "headers", None) or {}
    link = headers.get("link") or headers.get("Link") or ""
    if not link:
        return None
    for part in link.split(","):
        if 'rel="next"' not in part:
            continue
        url_segment = part.split(";", 1)[0].strip().lstrip("<").rstrip(">")
        cursor = parse_qs(urlparse(url_segment).query).get("after", [None])[0]
        if cursor:
            return cursor
    return None


async def paginate(fetch):
    """Drain all pages of an SDK list call.

    `fetch` is a callable that accepts the `after` cursor (or None for
    the first page) and returns the SDK's standard `(items, resp, err)`
    tuple — or the 2-tuple early-error shape `(items, err)`. Follows the
    `Link: rel="next"` header until exhausted. The returned tuple is
    `(all_items, error)` — error is non-None only when a page fails
    to fetch.
    """
    all_items = []
    result = await fetch(None)
    err = result[-1]
    if err is not None:
        return [], err
    items = result[0]
    resp = result[1] if len(result) >= 3 else None
    all_items.extend(items or [])
    while True:
        cursor = next_after_cursor(resp)
        if not cursor:
            break
        result = await fetch(cursor)
        err = result[-1]
        if err is not None:
            return all_items, err
        items = result[0]
        resp = result[1] if len(result) >= 3 else None
        all_items.extend(items or [])
    return all_items, None
