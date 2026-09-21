"""Tests for the Prowler Hub tools.

The Hub sub-server uses its own httpx clients, so its failures never pass through
the Prowler API client. They still have to arrive as tool errors rather than as a
result object, which the protocol, the client and the model all read as a success.
"""

import pytest
from fastmcp import Client

CHECKS = "/api/check"
PROVIDERS = "/api/providers"
COMPLIANCE = "/api/compliance"
CHECK_ID = "s3_bucket_public_access"
HUB_CHECK = f"{CHECKS}/{CHECK_ID}"


def github_check(provider: str, suffix: str = ".py") -> str:
    """The raw.githubusercontent path a check artifact is fetched from."""
    return (
        f"/prowler-cloud/prowler/refs/heads/master/prowler/providers/{provider}"
        f"/services/s3/{CHECK_ID}/{CHECK_ID}{suffix}"
    )


GITHUB_CHECK = github_check("aws")
GITHUB_FIXER = github_check("aws", "_fixer.py")


async def test_listing_checks_returns_the_lightweight_shape(
    mcp_root_server, hub_router
):
    """The happy path, so the failure tests below are not the only coverage."""
    hub_router.add(
        "GET",
        CHECKS,
        json=[
            {
                "id": "s3_bucket_public_access",
                "provider": "aws",
                "title": "S3 buckets should block public access",
                "severity": "high",
            }
        ],
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_hub_list_checks", {})

    assert result.data["count"] == 1
    assert result.data["checks"][0]["id"] == "s3_bucket_public_access"


async def test_an_unknown_check_fails_and_names_the_tool_that_finds_one(
    mcp_root_server, hub_router
):
    """A 404 is the caller's mistake, and the fix is a different tool."""
    hub_router.add("GET", f"{CHECKS}/nope", status=404)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_details", {"check_id": "nope"}
        )

    assert result.isError is True
    assert "prowler_hub_semantic_search_checks" in result.content[0].text


async def test_an_unknown_provider_fails_and_lists_the_real_ones(
    mcp_root_server, hub_router
):
    """The valid values are already in hand, so withholding them wastes a call."""
    hub_router.add(
        "GET",
        PROVIDERS,
        json=[{"id": "aws", "name": "Amazon Web Services", "services": ["s3"]}],
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_provider_services", {"provider_id": "alicloud"}
        )

    assert result.isError is True
    assert "aws" in result.content[0].text


async def test_a_check_without_a_fixer_says_that_is_normal(mcp_root_server, hub_router):
    """Most checks have no auto-remediation, so this must not read as a defect."""
    hub_router.add("GET", GITHUB_FIXER, status=404)
    hub_router.add("GET", HUB_CHECK, json={"id": CHECK_ID, "provider": "aws"})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_fixer",
            {"provider_id": "aws", "check_id": CHECK_ID},
        )

    assert result.isError is True
    message = result.content[0].text
    assert "normal" in message
    # The Hub confirmed the check is an aws check, so nothing is left to verify.
    assert "prowler_hub_get_check_details" not in message


async def test_a_check_from_another_provider_names_the_provider_that_has_it(
    mcp_root_server, hub_router
):
    """The ID exists; only the provider is wrong. Saying otherwise sends the
    caller off to search for an ID they already hold."""
    hub_router.add("GET", github_check("azure"), status=404)
    hub_router.add("GET", HUB_CHECK, json={"id": CHECK_ID, "provider": "aws"})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_code",
            {"provider_id": "azure", "check_id": CHECK_ID},
        )

    assert result.isError is True
    message = result.content[0].text
    assert "provider_id='aws'" in message
    assert "No check with the ID" not in message


async def test_a_fixer_from_another_provider_is_not_reported_as_a_missing_fixer(
    mcp_root_server, hub_router
):
    """'That check has no fixer' about a check the provider never had is a lie
    the caller cannot act on."""
    hub_router.add("GET", github_check("azure", "_fixer.py"), status=404)
    hub_router.add("GET", HUB_CHECK, json={"id": CHECK_ID, "provider": "aws"})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_fixer",
            {"provider_id": "azure", "check_id": CHECK_ID},
        )

    assert result.isError is True
    message = result.content[0].text
    assert "provider_id='aws'" in message
    assert "auto-remediation" not in message


async def test_a_check_id_that_exists_nowhere_is_still_reported_as_unknown(
    mcp_root_server, hub_router
):
    """The Hub not having the ID either is the one case that does justify the
    original message."""
    hub_router.add("GET", github_check("azure"), status=404)
    hub_router.add("GET", HUB_CHECK, status=404)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_code",
            {"provider_id": "azure", "check_id": CHECK_ID},
        )

    assert result.isError is True
    assert "No check with the ID" in result.content[0].text


async def test_an_unreachable_hub_leaves_the_cause_open_rather_than_guessing(
    mcp_root_server, hub_router
):
    """With nothing to distinguish the causes, naming one of them is a guess."""
    hub_router.add("GET", github_check("azure"), status=404)
    hub_router.add("GET", HUB_CHECK, status=503)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_code",
            {"provider_id": "azure", "check_id": CHECK_ID},
        )

    assert result.isError is True
    message = result.content[0].text
    assert "No check with the ID" not in message
    assert "prowler_hub_get_check_details" in message


async def test_a_check_code_hit_never_asks_the_hub(mcp_root_server, hub_router):
    """The Hub lookup exists to explain a 404. On the happy path it is dead
    weight -- a second round trip for every call that already succeeded."""
    hub_router.add("GET", GITHUB_CHECK, text="class s3_bucket_public_access: ...")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_hub_get_check_code",
            {"provider_id": "aws", "check_id": CHECK_ID},
        )

    assert "class s3_bucket_public_access" in result.data["content"]
    assert hub_router.paths() == [f"GET {GITHUB_CHECK}"]


async def test_a_hub_outage_is_reported_rather_than_returned_as_an_empty_list(
    mcp_root_server, hub_router
):
    """An empty result set and a failed request are different answers."""
    hub_router.add("GET", CHECKS, status=500, json={"detail": "boom"})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_hub_list_checks", {})

    assert result.isError is True
    assert result.structuredContent is None


@pytest.mark.parametrize(
    ("check_id", "routed_as", "sent_as"),
    [
        ("../../evil", f"{CHECKS}/../../evil", b"/api/check/..%2F..%2Fevil"),
        ("s3/../evil", f"{CHECKS}/s3/../evil", b"/api/check/s3%2F..%2Fevil"),
        ("..", f"{CHECKS}/..", b"/api/check/%2E%2E"),
        (
            "s3_x?fields=all",
            f"{CHECKS}/s3_x?fields=all",
            b"/api/check/s3_x%3Ffields%3Dall",
        ),
        ("s3_x#frag", f"{CHECKS}/s3_x#frag", b"/api/check/s3_x%23frag"),
    ],
    ids=["traversal", "mid-path", "dot-segment", "query", "fragment"],
)
async def test_an_id_names_a_check_and_cannot_name_an_endpoint(
    mcp_root_server, hub_router, check_id, routed_as, sent_as
):
    """The bug this pins: httpx resolved "../.." away and the request left
    /api/check for another endpoint of the Hub."""
    hub_router.add("GET", routed_as, status=404)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_details", {"check_id": check_id}
        )

    assert hub_router.requests[0].url.raw_path == sent_as
    assert result.isError is True
    assert "No check with the ID" in result.content[0].text


async def test_a_compliance_id_cannot_name_an_endpoint_either(
    mcp_root_server, hub_router
):
    """Every Hub path is built by the same helper, so this holds without its own
    guard."""
    hub_router.add("GET", f"{COMPLIANCE}/../../evil", status=404)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_compliance_details", {"compliance_id": "../../evil"}
        )

    assert hub_router.requests[0].url.raw_path == b"/api/compliance/..%2F..%2Fevil"
    assert result.isError is True
    assert "No compliance framework with the ID" in result.content[0].text


async def test_a_check_source_url_confines_the_provider_and_the_check_alike(
    mcp_root_server, hub_router
):
    """Both halves of the GitHub raw URL come from the caller, so both are
    confined."""
    hub_router.add("GET", github_check("../../../../evil"), status=404)
    hub_router.add("GET", HUB_CHECK, json={"id": CHECK_ID, "provider": "aws"})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_code",
            {"provider_id": "../../../../evil", "check_id": CHECK_ID},
        )

    assert (
        hub_router.requests[0].url.raw_path
        == github_check("..%2F..%2F..%2F..%2Fevil").encode()
    )
    assert result.isError is True


async def test_a_hub_body_that_is_not_json_is_not_blamed_on_the_arguments(
    mcp_root_server, hub_router
):
    """An edge answering 200 with an HTML page decodes to the same
    `JSONDecodeError` a malformed argument does, and the two mean opposite
    things: nothing in this call can be corrected."""
    hub_router.add("GET", CHECKS, text="<html><body>502 Bad Gateway</body></html>")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp("prowler_hub_list_checks", {})

    assert result.isError is True
    message = result.content[0].text
    assert "hub.prowler.com" in message
    assert "could not read as JSON" in message
    assert "Bad Gateway" not in message
    assert "Send it as a real object" not in message


async def test_an_unreadable_hub_answer_does_not_become_an_unknown_check(
    mcp_root_server, hub_router
):
    """The 404 branch is the only one that may claim the ID does not exist. A
    body that could not be read says nothing about the ID."""
    hub_router.add("GET", HUB_CHECK, text="<html>not json</html>")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_details", {"check_id": CHECK_ID}
        )

    assert result.isError is True
    message = result.content[0].text
    assert "could not read as JSON" in message
    assert "No check with the ID" not in message


async def test_an_unreadable_hub_answer_leaves_a_missing_check_file_unexplained(
    mcp_root_server, hub_router
):
    """The Hub is asked which provider owns the check. A body it could not read
    is no more of an answer than an outage, so it hedges the same way."""
    hub_router.add("GET", github_check("azure"), status=404)
    hub_router.add("GET", HUB_CHECK, text="<html>not json</html>")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool_mcp(
            "prowler_hub_get_check_code",
            {"provider_id": "azure", "check_id": CHECK_ID},
        )

    assert result.isError is True
    message = result.content[0].text
    assert "No check with the ID" not in message
    assert "prowler_hub_get_check_details" in message
