"""Tests for the raw-JSON HTTP helpers in
`prowler.providers.okta.lib.service.raw_fetch`.

Covers `get_json` (single-shot) and `get_json_paginated`
(drains list endpoints via the `Link: rel="next"` cursor).
"""

import asyncio
import json
from unittest import mock

from prowler.providers.okta.lib.service.raw_fetch import (
    get_json,
    get_json_paginated,
)


def _run(coro):
    return asyncio.run(coro)


def _mock_response(headers: dict = None):
    r = mock.MagicMock()
    r.headers = headers or {}
    return r


class Test_get_json:
    def test_returns_parsed_json_on_success(self):
        client = mock.MagicMock()

        async def create(*_a, **_k):
            return ({"url": "/x"}, None)

        async def execute(_req):
            return (_mock_response(), json.dumps({"hello": "world"}), None)

        client._request_executor.create_request = create
        client._request_executor.execute = execute

        assert _run(get_json(client, "/x")) == {"hello": "world"}

    def test_returns_none_on_create_request_error(self):
        client = mock.MagicMock()

        async def create(*_a, **_k):
            return (None, Exception("boom"))

        client._request_executor.create_request = create
        assert _run(get_json(client, "/x")) is None

    def test_returns_none_on_execute_error(self):
        client = mock.MagicMock()

        async def create(*_a, **_k):
            return ({"url": "/x"}, None)

        async def execute(_req):
            return (_mock_response(), None, Exception("boom"))

        client._request_executor.create_request = create
        client._request_executor.execute = execute
        assert _run(get_json(client, "/x")) is None


class Test_get_json_paginated:
    def test_drains_all_pages_following_link_rel_next(self):
        # Two pages: first carries `Link: <…?after=cur1>; rel="next"`,
        # second has no `next`, so iteration stops.
        client = mock.MagicMock()

        page1 = [{"id": "a"}, {"id": "b"}]
        page2 = [{"id": "c"}]
        page1_headers = {
            "link": '<https://acme.okta.com/api/v1/items?after=cur1>; rel="next"'
        }

        seen_urls = []

        async def create(**kwargs):
            seen_urls.append(kwargs["url"])
            return ({"url": kwargs["url"]}, None)

        async def execute(request):
            if "after=cur1" in request["url"]:
                return (_mock_response({}), json.dumps(page2), None)
            return (_mock_response(page1_headers), json.dumps(page1), None)

        client._request_executor.create_request = create
        client._request_executor.execute = execute

        items = _run(get_json_paginated(client, "/api/v1/items", page_size=2))

        assert items == [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        assert len(seen_urls) == 2
        assert "limit=2" in seen_urls[0]
        # The cursor was carried into the second request.
        assert "after=cur1" in seen_urls[1]
        assert "limit=2" in seen_urls[1]

    def test_single_page_terminates_immediately(self):
        client = mock.MagicMock()

        async def create(**kwargs):
            return ({"url": kwargs["url"]}, None)

        async def execute(_req):
            return (_mock_response({}), json.dumps([{"id": "only"}]), None)

        client._request_executor.create_request = create
        client._request_executor.execute = execute

        assert _run(get_json_paginated(client, "/api/v1/items")) == [{"id": "only"}]

    def test_returns_none_when_response_is_not_a_list(self):
        client = mock.MagicMock()

        async def create(**kwargs):
            return ({"url": kwargs["url"]}, None)

        async def execute(_req):
            return (_mock_response({}), json.dumps({"error": "nope"}), None)

        client._request_executor.create_request = create
        client._request_executor.execute = execute

        assert _run(get_json_paginated(client, "/api/v1/items")) is None

    def test_preserves_existing_query_string_and_overrides_limit(self):
        # Caller already passes `type=USER_LIFECYCLE` — pagination must
        # merge `limit` without clobbering existing params.
        client = mock.MagicMock()
        seen = []

        async def create(**kwargs):
            seen.append(kwargs["url"])
            return ({"url": kwargs["url"]}, None)

        async def execute(_req):
            return (_mock_response({}), "[]", None)

        client._request_executor.create_request = create
        client._request_executor.execute = execute

        _run(
            get_json_paginated(
                client, "/api/v1/policies?type=USER_LIFECYCLE", page_size=50
            )
        )

        assert "type=USER_LIFECYCLE" in seen[0]
        assert "limit=50" in seen[0]
