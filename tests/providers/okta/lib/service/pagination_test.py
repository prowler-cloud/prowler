"""Tests for the shared Okta pagination helpers in
`prowler.providers.okta.lib.service.pagination`.

Covers `next_after_cursor` (extracts the `after` query param from an
RFC 5988 `Link: rel="next"` header) and `paginate` (drains all pages
of an SDK list call by following the cursor).

These tests were carved out of `network_zone_service_test.py` when its
local pagination helpers were replaced by the shared module — they now
cover code that six Okta services depend on.
"""

import asyncio
from types import SimpleNamespace

from prowler.providers.okta.lib.service.pagination import (
    next_after_cursor,
    paginate,
)


def _run(coro):
    return asyncio.run(coro)


def _resp(headers: dict = None):
    return SimpleNamespace(headers=headers or {})


class Test_next_after_cursor:
    """Behaviours previously covered in `network_zone_service_test.py`
    under `Test_network_zone_pagination` — relocated here when the
    local helper was replaced by the shared module.
    """

    def test_returns_none_when_response_is_none(self):
        assert next_after_cursor(None) is None

    def test_returns_none_when_no_link_header(self):
        assert next_after_cursor(_resp({})) is None

    def test_extracts_next_after_cursor(self):
        link = (
            '<https://acme.okta.com/api/v1/zones?limit=20>; rel="self", '
            '<https://acme.okta.com/api/v1/zones?after=next-page>; rel="next"'
        )
        assert next_after_cursor(_resp({"Link": link})) == "next-page"

    def test_reads_lowercase_link_header(self):
        # aiohttp's `CIMultiDict` is case-insensitive in practice, but
        # callers occasionally pass a dict, so we check both spellings.
        link = '<https://acme.okta.com/api/v1/zones?after=cursor-1>; rel="next"'
        assert next_after_cursor(_resp({"link": link})) == "cursor-1"

    def test_next_link_without_after_query_returns_none(self):
        link = (
            '<https://acme.okta.com/api/v1/zones?limit=20>; rel="self", '
            '<https://acme.okta.com/api/v1/zones?limit=20>; rel="next"'
        )
        assert next_after_cursor(_resp({"Link": link})) is None

    def test_no_next_segment_returns_none(self):
        link = '<https://acme.okta.com/api/v1/zones?after=ignored>; rel="self"'
        assert next_after_cursor(_resp({"Link": link})) is None

    def test_url_decodes_after_cursor(self):
        # `parse_qs` decodes percent-encoded values — opaque cursors with
        # `=` or `+` must round-trip through callers that re-encode.
        link = (
            "<https://acme.okta.com/api/v1/zones?after=cursor%3Dabc%2B1>; " 'rel="next"'
        )
        assert next_after_cursor(_resp({"Link": link})) == "cursor=abc+1"


class Test_paginate:
    def test_returns_items_for_single_page_response(self):
        async def fetch(_after):
            return (["a", "b"], _resp({}), None)

        items, err = _run(paginate(fetch))
        assert items == ["a", "b"]
        assert err is None

    def test_drains_multiple_pages(self):
        link = '<https://acme.okta.com/api/v1/x?after=p2>; rel="next"'
        seen_cursors: list = []

        async def fetch(after):
            seen_cursors.append(after)
            if after is None:
                return (["a"], _resp({"link": link}), None)
            return (["b"], _resp({}), None)

        items, err = _run(paginate(fetch))
        assert items == ["a", "b"]
        assert err is None
        assert seen_cursors == [None, "p2"]

    def test_returns_empty_when_first_page_is_empty(self):
        async def fetch(_after):
            return ([], _resp({}), None)

        items, err = _run(paginate(fetch))
        assert items == []
        assert err is None

    def test_returns_empty_and_error_when_first_page_fails(self):
        async def fetch(_after):
            return ([], _resp({}), Exception("forbidden"))

        items, err = _run(paginate(fetch))
        assert items == []
        assert str(err) == "forbidden"

    def test_returns_partial_items_when_subsequent_page_errors(self):
        # Carved out of `network_zone_service_test.py`'s
        # `test_pagination_returns_partial_items_when_second_page_errors`.
        link = '<https://acme.okta.com/api/v1/x?after=p2>; rel="next"'

        async def fetch(after):
            if after is None:
                return (["page-1"], _resp({"link": link}), None)
            return ([], _resp({}), Exception("page failed"))

        items, err = _run(paginate(fetch))
        assert items == ["page-1"]
        assert str(err) == "page failed"

    def test_accepts_early_error_two_tuple_shape(self):
        # The Okta SDK returns `(items, err)` on request-build failures
        # (no response) and `(items, resp, err)` on transport responses.
        # `paginate` reads `result[-1]` for err so the 2-tuple shape is
        # handled — verify explicitly.
        async def fetch(_after):
            return ([], Exception("create failed"))

        items, err = _run(paginate(fetch))
        assert items == []
        assert str(err) == "create failed"

    def test_treats_none_items_as_empty_list(self):
        async def fetch(_after):
            return (None, _resp({}), None)

        items, err = _run(paginate(fetch))
        assert items == []
        assert err is None
