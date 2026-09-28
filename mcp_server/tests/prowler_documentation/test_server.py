"""Tests for the Prowler documentation tools.

Mintlify moved the docs search to a new endpoint that answers with page
sections, so a result is a part of a page and has to read as one. And a failed
request must not reach an agent as "the documentation has nothing on this",
which is an answer it would act on, confidently and wrongly.
"""

import json

from fastmcp import Client

SEARCH = "/api/search/prowler"
DOC = "/getting-started/installation.md"


def search_match(
    path: str = "getting-started/installation",
    *,
    header: str = "Requirements",
    breadcrumbs: tuple[str, ...] = ("Get Started", "Installation"),
    anchor: str | None = "requirements",
    score: float = 4.9,
):
    """One match as Mintlify answers with it: a section of a page, not the page."""
    return {
        "page": path,
        "header": header,
        "content": "Prowler runs on Python 3.9 or later.",
        "metadata": {
            "title": header,
            "breadcrumbs": list(breadcrumbs),
            "icon": "",
            "hash": anchor,
            "openapi": "",
        },
        "score": score,
    }


def stub_search_hit(docs_router, *matches):
    """Serve the search endpoint, with one default match when none are given."""
    if not matches:
        matches = (search_match(),)
    return docs_router.add("POST", SEARCH, json={"results": list(matches)})


async def test_search_returns_the_matching_sections(mcp_root_server, docs_router):
    """Every field of a result, since the shape of one changed with the endpoint."""
    stub_search_hit(docs_router)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_docs_search", {"term": "install"})

    match = result.data[0]
    assert match["path"] == "getting-started/installation"
    # The page's title, so a result reads as more than the heading it matched.
    assert match["title"] == "Installation"
    assert match["section"] == "Requirements"
    assert match["breadcrumbs"] == ["Get Started", "Installation"]
    assert match["excerpt"] == "Prowler runs on Python 3.9 or later."
    assert match["score"] == 4.9
    # Anchored: a match is a section, and the page it is on can be a long one.
    assert match["url"] == (
        "https://docs.prowler.com/getting-started/installation#requirements"
    )


async def test_the_search_query_is_sent_as_the_api_expects_it(
    mcp_root_server, docs_router
):
    """The endpoint takes a POST body, not the payload the old one took."""
    stub_search_hit(docs_router)

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_docs_search", {"term": "install"})

    request = docs_router.request_for("POST", SEARCH)
    assert json.loads(request.content) == {"query": "install", "filters": {}}


async def test_a_section_with_no_anchor_links_to_the_page(mcp_root_server, docs_router):
    """The API sends "" for a page's first section and null for pages without anchors."""
    stub_search_hit(
        docs_router,
        search_match(anchor=""),
        search_match(path="getting-started/requirements", anchor=None),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_docs_search", {"term": "install"})

    assert result.data[0]["url"] == (
        "https://docs.prowler.com/getting-started/installation"
    )
    assert result.data[1]["url"] == (
        "https://docs.prowler.com/getting-started/requirements"
    )


async def test_page_size_caps_a_response_the_api_did_not_size(
    mcp_root_server, docs_router
):
    """The endpoint takes no size argument, so the cap has to be applied here."""
    stub_search_hit(docs_router, *(search_match() for _ in range(6)))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_docs_search", {"term": "install", "page_size": 2}
        )

    assert len(result.data) == 2


async def test_a_search_that_failed_is_not_reported_as_no_matches(
    mcp_root_server, docs_router
):
    """An empty list is an answer. A failed request is not, and must not look like one."""
    docs_router.add("POST", SEARCH, status=500, text="upstream error")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_docs_search", {"term": "install"})

    assert result.isError is True
    assert result.structuredContent is None


async def test_a_missing_page_fails_and_names_the_tool_that_finds_a_valid_path(
    mcp_root_server, docs_router
):
    """A 404 answers the question, and still reaches the agent as an error."""
    docs_router.add("GET", DOC, status=404, text="Not Found")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_docs_get_document", {"doc_path": "getting-started/installation"}
        )

    assert result.isError is True
    assert "prowler_docs_search" in result.content[0].text


async def test_a_fetch_that_failed_is_not_reported_as_a_missing_page(
    mcp_root_server, docs_router
):
    """Only a 404 answers the question; every other status left it unanswered."""
    docs_router.add("GET", DOC, status=503, text="upstream error")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_docs_get_document", {"doc_path": "getting-started/installation"}
        )

    assert result.isError is True
    assert "no page at" not in result.content[0].text


async def test_an_unreadable_body_is_not_reported_as_a_bad_search_term(
    mcp_root_server, docs_router
):
    """An edge serving HTML is the site's fault; the caller has no term to fix."""
    docs_router.add("POST", SEARCH, status=200, text="<html>edge error page</html>")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_docs_search", {"term": "install"})

    assert result.isError is True
    message = result.content[0].text
    # Named as the upstream at fault, and explicitly not the caller's arguments,
    # which is the story the shared ValueError branch would otherwise tell.
    assert "leaves.mintlify.com" in message
    assert "changing them will not help" in message
    # The body it choked on is upstream text, which this server never relays.
    assert "edge error page" not in message
