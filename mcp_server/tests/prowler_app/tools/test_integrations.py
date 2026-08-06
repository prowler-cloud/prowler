"""Tests for the integrations tools.

These tools are the only write surface in the MCP server that reaches a system
Prowler does not own -- an S3 bucket, a Security Hub account, a Jira project --
so what goes out on the wire matters as much as what comes back. Three things
drive most of the assertions here:

* Creating or updating an integration is a multi-request choreography (write,
  connection check, task poll, re-read). ``mock_router.paths()`` is what pins it;
  a skipped connection check leaves a Jira integration with no discovered
  projects and is invisible in the response body.
* The API *replaces* credentials and configuration wholesale, so the guards that
  refuse a partial payload are protecting stored secrets, not just being tidy.
* A Jira dispatch creates work items one at a time and Prowler cannot delete
  them, so ``safe_to_retry`` must never be optimistic.

As in ``test_findings``, tools are driven through an in-memory MCP client so
FastMCP resolves the pydantic ``Field`` defaults.
"""

import httpx
import pytest
from fastmcp import Client

from tests.helpers.http import MockRouter
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_document,
    jsonapi_error,
    jsonapi_relationship_many,
    jsonapi_resource,
)

INTEGRATIONS = "/api/v1/integrations"
INTEGRATION = f"{INTEGRATIONS}/i1"
CONNECTION = f"{INTEGRATION}/connection"
DISPATCHES = f"{INTEGRATION}/jira/dispatches"
ISSUE_TYPES = f"{INTEGRATION}/jira/issue_types"
TASK = "/api/v1/tasks/t1"

S3_ATTRIBUTES = {
    "integration_type": "amazon_s3",
    "enabled": True,
    "connected": True,
    "connection_last_checked_at": "2025-01-15T10:00:00Z",
    "configuration": {"bucket_name": "my-reports", "output_directory": "prowler"},
}

SECURITY_HUB_ATTRIBUTES = {
    "integration_type": "aws_security_hub",
    "enabled": True,
    "connected": True,
    "configuration": {
        "send_only_fails": False,
        "archive_previous_findings": True,
        "regions": {"us-east-1": True, "eu-west-1": False},
    },
}

JIRA_ATTRIBUTES = {
    "integration_type": "jira",
    "enabled": True,
    "connected": True,
    "configuration": {
        "domain": "acme",
        "projects": {"PROJ": "Security"},
        "issue_types": {"PROJ": ["Task", "Bug"]},
    },
}


def stub_integration(
    mock_router: MockRouter,
    attributes: dict,
    *,
    provider_ids: tuple[str, ...] = (),
) -> MockRouter:
    """Serve ``GET /integrations/i1`` for every read a tool makes.

    A single registration is enough because the router repeats its last response,
    and the tools read the integration both before and after a write. Call it
    twice to serve a different state to each read, which is what tells the state
    returned after a write apart from the one read before it.
    """
    relationships = (
        {"providers": jsonapi_relationship_many("providers", *provider_ids)}
        if provider_ids
        else None
    )
    return mock_router.add(
        "GET",
        INTEGRATION,
        json=jsonapi_document(
            jsonapi_resource("integrations", "i1", attributes, relationships)
        ),
    )


def stub_connection_check(
    mock_router: MockRouter, *, connected: bool = True, error: str | None = None
) -> MockRouter:
    """Serve the check as Prowler runs it: a POST that returns a task to poll."""
    result: dict = {"connected": connected}
    if error is not None:
        result["error"] = error

    mock_router.add(
        "POST", CONNECTION, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )
    return mock_router.add(
        "GET",
        TASK,
        json=jsonapi_document(
            jsonapi_resource("tasks", "t1", {"state": "completed", "result": result})
        ),
    )


# ------------------------------------------------------------------ read tools


async def test_listing_does_not_ask_for_the_configuration(
    mcp_root_server, mock_api_client, mock_router
):
    """The sparse fieldset is what keeps a list of integrations small.

    A Jira configuration carries every project and every issue type of the site,
    which is the bulk of the payload and useless until an agent has picked one
    integration to work with -- that is what prowler_get_integration is for.
    """
    mock_router.add("GET", INTEGRATIONS, json=jsonapi_collection([]))

    async with Client(mcp_root_server) as client:
        await client.call_tool("prowler_list_integrations", {})

    params = mock_router.query_params("GET", INTEGRATIONS)
    assert "configuration" not in params["fields[integrations]"]
    assert params["page[size]"] == "50"
    assert params["page[number]"] == "1"


async def test_listing_filters_by_type_with_a_comma_separated_value(
    mcp_root_server, mock_api_client, mock_router
):
    """Multi-value filters reach the API as CSV, not as repeated query keys."""
    mock_router.add(
        "GET",
        INTEGRATIONS,
        json=jsonapi_collection(
            [jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)]
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_list_integrations", {"integration_type": ["amazon_s3", "jira"]}
        )

    params = mock_router.query_params("GET", INTEGRATIONS)
    assert params["filter[integration_type__in]"] == "amazon_s3,jira"
    assert result.data["integrations"][0]["integration_type"] == "amazon_s3"


async def test_getting_an_integration_returns_its_configuration(
    mcp_root_server, mock_api_client, mock_router
):
    """The configuration is the whole reason this tool exists next to the list."""
    stub_integration(mock_router, JIRA_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_get_integration", {"integration_id": "i1"}
        )

    assert result.data["configuration"]["projects"] == {"PROJ": "Security"}


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"data": None}, "was not found"),
        ({"data": {"type": "integrations", "id": "i1"}}, "without its attributes"),
    ],
    ids=["no-resource", "no-attributes"],
)
async def test_an_unusable_integration_payload_is_rejected_with_a_next_step(
    mcp_root_server, mock_api_client, mock_router, document, message
):
    """Both shapes arrive as a 200, so neither raises on its own.

    Left alone they surface as an opaque attribute error somewhere downstream
    instead of telling the agent to go look the ID up. The two are reported
    differently because a missing resource is the caller's mistake and a resource
    without attributes is the API's.
    """
    mock_router.add("GET", INTEGRATION, json=document)

    async with Client(mcp_root_server) as client:
        with pytest.raises(Exception, match=message):
            await client.call_tool("prowler_get_integration", {"integration_id": "i1"})


# ---------------------------------------------------------------- create tools


async def test_creating_an_s3_integration_checks_the_connection_before_returning(
    mcp_root_server, mock_api_client, mock_router
):
    """Creation is a write, a connection check, a task poll and a re-read.

    The check is not optional: it is what proves the bucket policy lets Prowler
    write, and skipping it would report a broken integration as ready.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        json=jsonapi_document(jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)),
    )
    stub_connection_check(mock_router)
    stub_integration(mock_router, S3_ATTRIBUTES, provider_ids=("p1",))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_create_amazon_s3_integration",
            {"bucket_name": "my-reports", "provider_ids": ["p1"]},
        )

    assert result.data["connected"] == "connected"
    assert result.data["integration"]["id"] == "i1"
    assert mock_router.paths() == [
        f"POST {INTEGRATIONS}",
        f"POST {CONNECTION}",
        f"GET {TASK}",
        f"GET {INTEGRATION}",
    ]


async def test_creating_an_s3_integration_sends_only_the_credentials_given(
    mcp_root_server, mock_api_client, mock_router
):
    """Omitted credentials must be absent, not present and null.

    An empty credentials object is a meaningful instruction -- use the ambient
    AWS credentials of the deployment -- so sending nulls for the keys the caller
    left out would be rejected instead of falling back.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        json=jsonapi_document(jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)),
    )
    stub_connection_check(mock_router)
    stub_integration(mock_router, S3_ATTRIBUTES, provider_ids=("p1",))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_create_amazon_s3_integration",
            {
                "bucket_name": "my-reports",
                "provider_ids": ["p1"],
                "role_arn": "arn:aws:iam::123456789012:role/ProwlerS3Integration",
            },
        )

    data = mock_router.json_body("POST", INTEGRATIONS)["data"]
    assert data["attributes"]["credentials"] == {
        "role_arn": "arn:aws:iam::123456789012:role/ProwlerS3Integration",
        "session_duration": 3600,
    }
    assert data["attributes"]["configuration"] == {
        "bucket_name": "my-reports",
        "output_directory": "output",
    }
    assert data["relationships"]["providers"]["data"] == [
        {"type": "providers", "id": "p1"}
    ]


async def test_creating_a_jira_integration_reduces_a_site_url_to_its_name(
    mcp_root_server, mock_api_client, mock_router
):
    """The API only accepts the bare site name, and a URL is what people paste.

    It also rejects any configuration in the payload, since it generates it from
    the connection check.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        json=jsonapi_document(jsonapi_resource("integrations", "i1", JIRA_ATTRIBUTES)),
    )
    stub_connection_check(mock_router)
    stub_integration(mock_router, JIRA_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_create_jira_integration",
            {
                "domain": "https://acme.atlassian.net/jira/software",
                "user_mail": "security@acme.com",
                "api_token": "fake-atlassian-token-for-testing",
            },
        )

    attributes = mock_router.json_body("POST", INTEGRATIONS)["data"]["attributes"]
    assert attributes["credentials"]["domain"] == "acme"
    assert attributes["configuration"] == {}


async def test_creating_a_jira_integration_rejects_an_empty_domain(
    mcp_root_server, mock_api_client, mock_router
):
    """A domain that normalizes to nothing is caught before the round trip."""
    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_create_jira_integration",
            {
                "domain": "https://",
                "user_mail": "security@acme.com",
                "api_token": "fake-atlassian-token-for-testing",
            },
        )

    assert result.data["status"] == "failed"
    assert "Invalid Jira domain" in result.data["error"]
    assert mock_router.requests == []


@pytest.mark.parametrize(
    ("tool", "arguments"),
    [
        ("prowler_create_aws_security_hub_integration", {"provider_id": "p1"}),
        ("prowler_create_amazon_s3_integration", {"bucket_name": "my-reports"}),
    ],
    ids=["security-hub", "amazon-s3"],
)
async def test_a_rejected_creation_is_reported_rather_than_raised(
    mcp_root_server, mock_api_client, mock_router, tool, arguments
):
    """Write tools answer with an error object so the agent can act on it.

    A raised exception reaches the model as a tool failure with no detail, and
    the API's message is exactly what tells it what to do next.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        status=409,
        json=jsonapi_error(409, "This provider already has this integration."),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(tool, arguments)

    assert result.data["status"] == "failed"
    assert "already has this integration" in result.data["error"]


async def test_a_creation_with_no_id_back_warns_before_a_blind_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """The integration may well exist, so retrying could create a second one.

    Without the ID there is nothing to check its connection with either, which
    makes "look it up before trying again" the only safe instruction.
    """
    mock_router.add("POST", INTEGRATIONS, json={"data": {}})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_create_amazon_s3_integration", {"bucket_name": "my-reports"}
        )

    assert result.data["status"] == "failed"
    assert "did not return its ID" in result.data["error"]
    assert mock_router.paths() == [f"POST {INTEGRATIONS}"]


async def test_a_creation_whose_read_back_fails_still_hands_over_the_id(
    mcp_root_server, mock_api_client, mock_router
):
    """The integration was created; only reading it back went wrong.

    Reporting the read failure alone would read as "creation failed" and invite a
    duplicate, so the error carries the ID the agent needs to go and inspect it.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        json=jsonapi_document(jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)),
    )
    stub_connection_check(mock_router)
    mock_router.add(
        "GET", INTEGRATION, status=500, json=jsonapi_error(500, "Server error.")
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_create_amazon_s3_integration", {"bucket_name": "my-reports"}
        )

    assert result.data["status"] == "failed"
    assert "Integration i1 was created" in result.data["error"]


async def test_a_connection_check_that_cannot_run_is_not_reported_as_a_failure(
    mcp_root_server, mock_api_client, mock_router
):
    """`not_tested` says nothing about the credentials, and that is the point.

    Reporting it as `failed` would send an agent rewriting credentials that were
    never actually exercised.
    """
    mock_router.add(
        "POST",
        INTEGRATIONS,
        json=jsonapi_document(jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)),
    )
    # Accepted, but without the task ID there is nothing to poll
    mock_router.add("POST", CONNECTION, json={"data": {}})
    stub_integration(mock_router, S3_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_create_amazon_s3_integration", {"bucket_name": "my-reports"}
        )

    assert result.data["connected"] == "not_tested"
    assert "could not be completed" in result.data["error"]


# ---------------------------------------------------------------- update tool


async def test_updating_only_the_enabled_flag_does_not_recheck_the_connection(
    mcp_root_server, mock_api_client, mock_router
):
    """Nothing about reachability changed, so the check would be pure latency.

    It is also destructive to spend: the check is a background task the tool
    waits on for up to two minutes. Skipping the check must not also skip the
    read-back, though: the PATCH response body is empty, so returning the state
    read before the write would report the integration as still enabled.
    """
    # The read before the PATCH, then the read after it
    stub_integration(mock_router, S3_ATTRIBUTES)
    stub_integration(mock_router, {**S3_ATTRIBUTES, "enabled": False})
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration", {"integration_id": "i1", "enabled": False}
        )

    assert mock_router.json_body("PATCH", INTEGRATION)["data"]["attributes"] == {
        "enabled": False
    }
    assert f"POST {CONNECTION}" not in mock_router.paths()
    assert result.data["enabled"] is False


async def test_updating_the_configuration_merges_it_onto_the_current_one(
    mcp_root_server, mock_api_client, mock_router
):
    """The API replaces the configuration wholesale, so a partial one loses keys.

    The server-owned regions are stripped back out: they are refreshed by the
    connection check, and sending them back would fight the API for ownership.
    """
    # The read before the PATCH, then the read after it
    stub_integration(mock_router, SECURITY_HUB_ATTRIBUTES, provider_ids=("p1",))
    stub_integration(
        mock_router,
        {
            **SECURITY_HUB_ATTRIBUTES,
            "configuration": {
                **SECURITY_HUB_ATTRIBUTES["configuration"],
                "send_only_fails": True,
            },
        },
        provider_ids=("p1",),
    )
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))
    stub_connection_check(mock_router)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "configuration": {"send_only_fails": True}},
        )

    assert mock_router.json_body("PATCH", INTEGRATION)["data"]["attributes"][
        "configuration"
    ] == {"send_only_fails": True, "archive_previous_findings": True}
    assert result.data["connected"] == "connected"
    # Read back after the write, so the response carries the merge the API applied
    assert result.data["integration"]["configuration"]["send_only_fails"] is True


async def test_a_configuration_sent_as_a_json_string_is_accepted(
    mcp_root_server, mock_api_client, mock_router
):
    """Some MCP clients cannot pass an object and send its JSON text instead.

    Rejecting those outright would make the tool unusable from those clients,
    which is why the parameter is typed to accept both.
    """
    stub_integration(mock_router, S3_ATTRIBUTES)
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))
    stub_connection_check(mock_router)

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "configuration": '{"bucket_name": "new-reports"}'},
        )

    assert (
        mock_router.json_body("PATCH", INTEGRATION)["data"]["attributes"][
            "configuration"
        ]["bucket_name"]
        == "new-reports"
    )


@pytest.mark.parametrize(
    ("configuration", "message"),
    [
        ("bucket_name=new", "Invalid JSON for configuration"),
        ('["bucket_name"]', "configuration must be a JSON object"),
    ],
    ids=["not-json", "json-but-not-an-object"],
)
async def test_a_configuration_that_is_not_an_object_is_rejected_before_the_write(
    mcp_root_server, mock_api_client, mock_router, configuration, message
):
    """Half-parsed text must not reach the API as a replacement configuration.

    Valid JSON is not enough: the configuration is merged key by key, so a list
    or a bare scalar would fail somewhere less obvious than here.
    """
    stub_integration(mock_router, S3_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "configuration": configuration},
        )

    assert result.data["status"] == "failed"
    assert message in result.data["error"]
    assert f"PATCH {INTEGRATION}" not in mock_router.paths()


async def test_clearing_aws_credentials_is_allowed_and_means_something(
    mcp_root_server, mock_api_client, mock_router
):
    """An empty object is a valid instruction for the AWS integration types.

    It falls back to the ambient credentials of the deployment, which is why the
    Jira guard against an empty object must not apply here.
    """
    stub_integration(mock_router, S3_ATTRIBUTES)
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))
    stub_connection_check(mock_router)

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "credentials": {}},
        )

    assert (
        mock_router.json_body("PATCH", INTEGRATION)["data"]["attributes"]["credentials"]
        == {}
    )


async def test_reordering_the_same_providers_does_not_recheck_the_connection(
    mcp_root_server, mock_api_client, mock_router
):
    """The providers decide the effective credentials, so a real change matters.

    Comparing them as sets keeps a re-sent list from paying for a two-minute
    connection check that can only confirm what is already known.
    """
    stub_integration(mock_router, S3_ATTRIBUTES, provider_ids=("p1", "p2"))
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "provider_ids": ["p2", "p1"]},
        )

    assert f"POST {CONNECTION}" not in mock_router.paths()


async def test_attaching_a_different_provider_rechecks_the_connection(
    mcp_root_server, mock_api_client, mock_router
):
    """A different provider means different credentials and a stale check result."""
    stub_integration(mock_router, S3_ATTRIBUTES, provider_ids=("p1",))
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))
    stub_connection_check(mock_router, connected=False, error="Access denied.")

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "provider_ids": ["p2"]},
        )

    assert mock_router.json_body("PATCH", INTEGRATION)["data"]["relationships"] == {
        "providers": {"data": [{"type": "providers", "id": "p2"}]}
    }
    assert result.data["connected"] == "failed"
    assert result.data["error"] == "Access denied."


async def test_an_update_with_nothing_to_change_returns_the_current_state(
    mcp_root_server, mock_api_client, mock_router
):
    """An empty PATCH would still cost a write and a connection check."""
    stub_integration(mock_router, S3_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration", {"integration_id": "i1"}
        )

    assert result.data["id"] == "i1"
    assert mock_router.paths() == [f"GET {INTEGRATION}"]


async def test_updating_a_jira_configuration_is_refused(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler generates the Jira configuration from the connection check.

    Sending one would overwrite the discovered projects and issue types, leaving
    an integration that looks fine but can no longer dispatch a finding.
    """
    stub_integration(mock_router, JIRA_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "configuration": {"domain": "other"}},
        )

    assert result.data["status"] == "failed"
    assert "do not accept a configuration" in result.data["error"]
    assert f"PATCH {INTEGRATION}" not in mock_router.paths()


async def test_attaching_a_jira_integration_to_a_provider_is_refused(
    mcp_root_server, mock_api_client, mock_router
):
    """Jira is tenant-wide; the API would reject this after a wasted round trip."""
    stub_integration(mock_router, JIRA_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "provider_ids": ["p1"]},
        )

    assert "tenant-wide" in result.data["error"]
    assert f"PATCH {INTEGRATION}" not in mock_router.paths()


@pytest.mark.parametrize(
    "provider_ids", [[], ["p1", "p2"]], ids=["detach-all", "two-providers"]
)
async def test_security_hub_must_keep_exactly_one_provider(
    mcp_root_server, mock_api_client, mock_router, provider_ids
):
    """The integration cannot exist without its provider.

    Detaching it through an update leaves the API to decide what that means; the
    supported way to stop sending findings is to delete the integration.
    """
    stub_integration(mock_router, SECURITY_HUB_ATTRIBUTES, provider_ids=("p1",))

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "provider_ids": provider_ids},
        )

    assert "exactly one AWS provider" in result.data["error"]
    assert f"PATCH {INTEGRATION}" not in mock_router.paths()


@pytest.mark.parametrize(
    "credentials",
    [{}, {"domain": "acme"}, {"domain": "acme", "user_mail": "", "api_token": "t"}],
    ids=["empty", "partial", "blank-value"],
)
async def test_partial_jira_credentials_are_refused_to_protect_the_stored_ones(
    mcp_root_server, mock_api_client, mock_router, credentials
):
    """The API replaces the credentials object as a whole.

    So a partial update does not patch the secret, it destroys it -- and the
    integration cannot be repaired without the original API token.
    """
    stub_integration(mock_router, JIRA_ATTRIBUTES)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_update_integration",
            {"integration_id": "i1", "credentials": credentials},
        )

    assert "replaced as a whole" in result.data["error"]
    assert f"PATCH {INTEGRATION}" not in mock_router.paths()


async def test_replacing_jira_credentials_normalizes_the_domain(
    mcp_root_server, mock_api_client, mock_router
):
    """The same URL-to-site-name reduction the creation tool applies.

    Without it a credentials replacement would store a domain the API cannot use,
    breaking an integration that was working.
    """
    stub_integration(mock_router, JIRA_ATTRIBUTES)
    mock_router.add("PATCH", INTEGRATION, json=jsonapi_document({}))
    stub_connection_check(mock_router)

    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_update_integration",
            {
                "integration_id": "i1",
                "credentials": {
                    "domain": "https://acme.atlassian.net",
                    "user_mail": "security@acme.com",
                    "api_token": "fake-atlassian-token-for-testing",
                },
            },
        )

    credentials = mock_router.json_body("PATCH", INTEGRATION)["data"]["attributes"][
        "credentials"
    ]
    assert credentials["domain"] == "acme"


# ------------------------------------------------- delete and connection tools


async def test_deleting_an_integration_reports_the_outcome_either_way(
    mcp_root_server, mock_api_client, mock_router
):
    """Deletion is irreversible, so both outcomes are stated explicitly.

    A bare exception would leave the agent unsure whether the credentials are
    gone, and a retry of a delete that actually succeeded reads as a new failure.
    """
    mock_router.add("DELETE", INTEGRATION, status=204)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_delete_integration", {"integration_id": "i1"}
        )

    assert result.data["deleted"] is True


async def test_a_failed_deletion_says_it_did_not_happen(
    mcp_root_server, mock_api_client, mock_router
):
    """`deleted: false` is the part the agent must not have to infer."""
    mock_router.add(
        "DELETE", INTEGRATION, status=403, json=jsonapi_error(403, "Permission denied.")
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_delete_integration", {"integration_id": "i1"}
        )

    assert result.data["deleted"] is False
    assert "Permission denied." in result.data["message"]


async def test_checking_a_connection_surfaces_why_it_failed(
    mcp_root_server, mock_api_client, mock_router
):
    """The error is the actionable half of a failed check."""
    stub_connection_check(
        mock_router, connected=False, error="Integration is not enabled"
    )
    stub_integration(
        mock_router, {**S3_ATTRIBUTES, "enabled": False, "connected": False}
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_test_integration_connection", {"integration_id": "i1"}
        )

    assert result.data["connected"] == "failed"
    assert result.data["error"] == "Integration is not enabled"
    # The re-read is what makes the refreshed configuration part of the answer
    assert mock_router.paths() == [
        f"POST {CONNECTION}",
        f"GET {TASK}",
        f"GET {INTEGRATION}",
    ]


# ------------------------------------------------------------------ jira tools


async def test_issue_types_are_requested_for_a_specific_project(
    mcp_root_server, mock_api_client, mock_router
):
    """Issue types differ per project, so the key has to reach the API."""
    mock_router.add(
        "GET",
        ISSUE_TYPES,
        json={"data": {"project_key": "PROJ", "issue_types": ["Task", "Bug"]}},
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_get_jira_issue_types",
            {"integration_id": "i1", "project_key": "PROJ"},
        )

    assert result.data["issue_types"] == ["Task", "Bug"]
    assert mock_router.query_params("GET", ISSUE_TYPES)["project_key"] == "PROJ"


async def test_dispatching_findings_sends_them_as_a_filter_not_a_body_field(
    mcp_root_server, mock_api_client, mock_router
):
    """The findings are selected by query filter; the body carries the target.

    Putting the IDs in the wrong half of the request is not an error the API
    reports -- it dispatches a different, unfiltered set of findings.
    """
    mock_router.add(
        "POST", DISPATCHES, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )
    mock_router.add(
        "GET",
        TASK,
        json=jsonapi_document(
            jsonapi_resource(
                "tasks",
                "t1",
                {
                    "state": "completed",
                    "result": {"created_count": 2, "failed_count": 0},
                },
            )
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1", "f2"],
            },
        )

    assert mock_router.query_params("POST", DISPATCHES)["filter[finding_id__in]"] == (
        "f1,f2"
    )
    assert mock_router.json_body("POST", DISPATCHES)["data"]["attributes"] == {
        "project_key": "PROJ",
        "issue_type": "Task",
    }
    assert result.data["created_count"] == 2
    assert result.data["safe_to_retry"] is False


async def test_dispatching_no_findings_is_refused_before_the_request(
    mcp_root_server, mock_api_client, mock_router
):
    """An empty filter would dispatch every finding the role can see."""
    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": [],
            },
        )

    assert result.data["status"] == "failed"
    assert result.data["safe_to_retry"] is True
    assert mock_router.requests == []


@pytest.mark.parametrize(
    "status", [400, 403, 404], ids=["invalid", "forbidden", "not-found"]
)
async def test_a_dispatch_the_api_refused_is_the_only_one_safe_to_retry(
    mcp_root_server, mock_api_client, mock_router, status
):
    """A client error is a refusal: the API rejects the dispatch before queueing it.

    That makes it the one dispatch failure an agent can act on directly, so the
    response has to say so -- an omitted `safe_to_retry` reads as "do not retry"
    and leaves fixing the issue type to a human.
    """
    mock_router.add(
        "POST",
        DISPATCHES,
        status=status,
        json=jsonapi_error(
            status, "Issue type 'Epic' requires fields Prowler cannot fill."
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Epic",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "failed"
    assert result.data["safe_to_retry"] is True
    assert "requires fields Prowler cannot fill" in result.data["error"]


async def test_a_dispatch_that_failed_on_the_server_is_not_safe_to_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """A server error is not a refusal, and this is where that distinction bites.

    The API queues the background task and only then serializes its answer, so a
    500 can come back with work items already being created. Treating every error
    status as a clean rejection would invite a resend on top of them.
    """
    mock_router.add(
        "POST", DISPATCHES, status=500, json=jsonapi_error(500, "Server error.")
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "unknown"
    assert result.data["safe_to_retry"] is False
    assert "Check the Jira project" in result.data["error"]


async def test_a_dispatch_request_that_got_no_answer_is_not_safe_to_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """A timeout is not a rejection either: the request may have been processed.

    Prowler could already be creating work items, so the only difference with a
    refused dispatch -- and the reason they cannot share a branch -- is that here
    nobody can say what was created.
    """

    def timed_out(request):
        raise httpx.ReadTimeout("Timed out reading the response", request=request)

    mock_router.add_handler("POST", DISPATCHES, timed_out)

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "unknown"
    assert result.data["safe_to_retry"] is False
    assert "Check the Jira project" in result.data["error"]


async def test_an_accepted_dispatch_with_no_task_id_is_not_safe_to_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """Prowler took the dispatch, so it is already creating work items.

    There is just no task to follow it with. Reporting that as a clean failure
    would invite a resend on top of whatever it created.
    """
    mock_router.add("POST", DISPATCHES, json={"data": {}})

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "unknown"
    assert result.data["safe_to_retry"] is False
    assert "task_id" not in result.data


async def test_a_dispatch_task_that_died_halfway_is_never_safe_to_retry(
    mcp_root_server, mock_api_client, mock_router
):
    """Work items are created one at a time and Prowler cannot delete them.

    A task that failed may have created any number of them first, so the honest
    answer is `unknown` plus a pointer at Jira -- never an invitation to resend.
    """
    mock_router.add(
        "POST", DISPATCHES, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )
    mock_router.add(
        "GET",
        TASK,
        json=jsonapi_document(
            jsonapi_resource("tasks", "t1", {"state": "failed", "error": "Jira 503"})
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "unknown"
    assert result.data["safe_to_retry"] is False
    assert result.data["task_id"] == "t1"


async def test_a_dispatch_still_running_when_the_wait_ends_reports_in_progress(
    mcp_root_server, mock_api_client, mock_router, monkeypatch
):
    """Giving up waiting is not the same as the dispatch stopping.

    It is still creating work items right now, so the response has to say so and
    hand back the task ID rather than let the agent conclude nothing happened.
    """
    from prowler_mcp_server.prowler_app.tools import integrations

    monkeypatch.setattr(integrations, "JIRA_DISPATCH_TIMEOUT", 0)
    mock_router.add(
        "POST", DISPATCHES, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )
    mock_router.add(
        "GET",
        TASK,
        json=jsonapi_document(jsonapi_resource("tasks", "t1", {"state": "executing"})),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "in_progress"
    assert result.data["safe_to_retry"] is False
    assert result.data["task_id"] == "t1"


async def test_a_completed_dispatch_with_no_counters_is_reported_as_unknown(
    mcp_root_server, mock_api_client, mock_router
):
    """Absent counters must not be read as zero.

    Zero created work items is precisely what makes a dispatch safe to retry, so
    defaulting them would invite the duplication this whole path exists to avoid.
    """
    mock_router.add(
        "POST", DISPATCHES, json=jsonapi_document(jsonapi_resource("tasks", "t1", {}))
    )
    mock_router.add(
        "GET",
        TASK,
        json=jsonapi_document(
            jsonapi_resource("tasks", "t1", {"state": "completed", "result": None})
        ),
    )

    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_send_findings_to_jira",
            {
                "integration_id": "i1",
                "project_key": "PROJ",
                "issue_type": "Task",
                "finding_ids": ["f1"],
            },
        )

    assert result.data["status"] == "unknown"
    assert result.data["safe_to_retry"] is False
