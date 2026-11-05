"""Tests for the integration models.

Two things here are not ordinary serialization and carry the weight of the
module: the Security Hub ``regions`` map, which is rewritten into the far smaller
``enabled_regions`` list before an agent ever sees it, and the Jira dispatch
result, whose ``safe_to_retry`` flag is the only thing standing between a
half-finished dispatch and a project full of duplicated work items.
"""

import pytest

from prowler_mcp_server.prowler_app.models.integrations import (
    DetailedIntegration,
    IntegrationConnectionStatus,
    IntegrationsListResponse,
    JiraDispatchResult,
    JiraIssueTypes,
    SimplifiedIntegration,
)
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_relationship_many,
    jsonapi_resource,
)

S3_ATTRIBUTES = {
    "integration_type": "amazon_s3",
    "enabled": True,
    "connected": True,
    "connection_last_checked_at": "2025-01-15T10:00:00Z",
    "inserted_at": "2025-01-10T09:00:00Z",
    "updated_at": "2025-01-15T10:00:00Z",
    "configuration": {"bucket_name": "my-reports", "output_directory": "prowler"},
}

SECURITY_HUB_ATTRIBUTES = {
    "integration_type": "aws_security_hub",
    "enabled": True,
    "connected": True,
    "configuration": {
        "send_only_fails": True,
        "archive_previous_findings": False,
        "regions": {"us-east-1": True, "eu-west-1": False, "eu-west-3": True},
    },
}

JIRA_ATTRIBUTES = {
    "integration_type": "jira",
    "enabled": True,
    "connected": None,
    "configuration": {"domain": "acme", "projects": {}, "issue_types": {}},
}


def test_simplified_integration_lifts_the_attached_provider_ids():
    """`provider_ids` comes from the relationship linkage, not the attributes.

    It is what tells an agent whether an integration covers the account it is
    looking at, so reading it out of the wrong place silently scopes every
    integration to the whole tenant.
    """
    integration = SimplifiedIntegration.from_api_response(
        jsonapi_resource(
            "integrations",
            "i1",
            S3_ATTRIBUTES,
            relationships={
                "providers": jsonapi_relationship_many("providers", "p1", "p2")
            },
        )
    )

    assert integration.provider_ids == ["p1", "p2"]
    assert integration.integration_type == "amazon_s3"


def test_a_never_checked_integration_still_reports_its_connected_field():
    """`connected: null` means "never checked", which is not "not connected".

    Every other empty value is dropped to save tokens, so without the override
    this field would vanish exactly when its absence is most misleading.
    """
    integration = SimplifiedIntegration.from_api_response(
        jsonapi_resource("integrations", "i1", {**JIRA_ATTRIBUTES, "connected": None})
    )

    dumped = integration.model_dump()

    assert dumped["connected"] is None
    # Contrast: an untouched empty field is dropped
    assert "connection_last_checked_at" not in dumped


def test_the_list_view_drops_a_configuration_the_api_still_sends():
    """The sparse fieldset asks the API to leave `configuration` out.

    The model must drop it anyway rather than pass it through: the fieldset is a
    request, not a guarantee, and a Jira configuration listing every project of
    the site is exactly what the separate detailed view exists to hold back.
    """
    integration = SimplifiedIntegration.from_api_response(
        jsonapi_resource("integrations", "i1", JIRA_ATTRIBUTES)
    )

    assert "configuration" not in integration.model_dump()


def test_security_hub_regions_are_collapsed_into_the_enabled_ones():
    """The API returns every region of the partition with a boolean.

    Only the enabled ones carry information, so the map is rewritten as a sorted
    list. Passing the raw map through would spend tokens listing dozens of
    regions to say "no".
    """
    integration = DetailedIntegration.from_api_response(
        jsonapi_resource("integrations", "i1", SECURITY_HUB_ATTRIBUTES)
    )

    assert integration.configuration["enabled_regions"] == ["eu-west-3", "us-east-1"]
    assert "regions" not in integration.configuration


def test_an_unexpected_regions_shape_is_preserved_rather_than_dropped():
    """A shape the rewrite does not understand is kept verbatim.

    Silently dropping it would hide a real API change behind an integration that
    merely looks like it has no regions enabled.
    """
    attributes = {
        **SECURITY_HUB_ATTRIBUTES,
        "configuration": {"regions": ["us-east-1"]},
    }

    integration = DetailedIntegration.from_api_response(
        jsonapi_resource("integrations", "i1", attributes)
    )

    assert integration.configuration["regions"] == ["us-east-1"]
    assert "enabled_regions" not in integration.configuration


def test_a_non_security_hub_configuration_is_passed_through_untouched():
    """Only Security Hub has a configuration worth rewriting."""
    integration = DetailedIntegration.from_api_response(
        jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)
    )

    assert integration.configuration == S3_ATTRIBUTES["configuration"]


def test_the_list_response_reports_the_pagination_of_the_whole_query():
    """Counts come from `meta.pagination`, not from the length of this page."""
    response = IntegrationsListResponse.from_api_response(
        jsonapi_collection(
            [jsonapi_resource("integrations", "i1", S3_ATTRIBUTES)],
            page=2,
            pages=3,
            count=7,
        )
    )

    assert [integration.id for integration in response.integrations] == ["i1"]
    assert (response.total_num_integrations, response.total_num_pages) == (7, 3)
    assert response.current_page == 2


@pytest.mark.parametrize(
    ("connected", "expected"),
    [(True, "connected"), (False, "failed"), (None, "not_tested")],
)
def test_the_connection_check_maps_its_tri_state_onto_a_readable_outcome(
    connected, expected
):
    """`null` is "the check did not run", which is not the same as a failure.

    Collapsing it onto `failed` would send an agent chasing credentials that were
    never actually tested.
    """
    status = IntegrationConnectionStatus.create(
        jsonapi_resource("integrations", "i1", S3_ATTRIBUTES),
        {"connected": connected},
    )

    assert status.connected == expected


def test_an_unreadable_connection_result_raises_instead_of_guessing():
    """Anything other than a boolean or null is an API change, not a failure."""
    with pytest.raises(ValueError, match="unexpected connection check result"):
        IntegrationConnectionStatus.create(
            jsonapi_resource("integrations", "i1", S3_ATTRIBUTES),
            {"connected": "yes"},
        )


def test_the_connection_error_is_only_reported_when_there_is_one():
    """A successful check must not carry an empty `error` key."""
    status = IntegrationConnectionStatus.create(
        jsonapi_resource("integrations", "i1", S3_ATTRIBUTES), {"connected": True}
    )

    assert "error" not in status.model_dump()


def test_jira_issue_types_are_read_from_a_wrapped_or_a_bare_payload():
    """This endpoint returns a non-model resource, so both shapes must work."""
    wrapped = JiraIssueTypes.from_api_response(
        jsonapi_resource(
            "jira-issue-types", "i1", {"project_key": "PROJ", "issue_types": ["Task"]}
        )
    )
    bare = JiraIssueTypes.from_api_response(
        {"project_key": "PROJ", "issue_types": ["Task"]}
    )

    assert (
        wrapped.model_dump()
        == bare.model_dump()
        == {
            "project_key": "PROJ",
            "issue_types": ["Task"],
        }
    )


def test_an_unreadable_issue_types_payload_raises():
    """Returning an empty list would read as "this project has no issue types"."""
    with pytest.raises(ValueError, match="unexpected Jira issue types payload"):
        JiraIssueTypes.from_api_response({"project_key": "PROJ"})


def test_a_dispatch_that_created_nothing_is_the_only_one_safe_to_retry():
    """Work items are created one by one and Prowler cannot delete them.

    So a retry is only safe when the run provably created none. Anything else
    duplicates work items in a project a human then has to clean up.
    """
    empty = JiraDispatchResult.from_task_result({"created_count": 0, "failed_count": 3})
    partial = JiraDispatchResult.from_task_result(
        {"created_count": 1, "failed_count": 2}
    )

    assert empty.safe_to_retry is True
    assert partial.safe_to_retry is False


def test_a_zero_count_survives_serialization():
    """Zero created work items is an outcome; an unknown count is not.

    The minimal serializer drops empty values, so without the override a fully
    failed dispatch would report no counts at all.
    """
    dumped = JiraDispatchResult.from_task_result(
        {"created_count": 0, "failed_count": 3}
    ).model_dump()

    assert dumped["created_count"] == 0
    assert dumped["failed_count"] == 3
    assert dumped["status"] == "completed"


@pytest.mark.parametrize(
    "result",
    [
        {"failed_count": 2},
        {"created_count": 1},
        {"created_count": "1", "failed_count": 0},
        None,
        "done",
    ],
    ids=["no-created", "no-failed", "not-an-int", "null", "not-an-object"],
)
def test_a_dispatch_result_without_usable_counters_raises(result):
    """Defaulting the counters to zero would report the run as safe to retry.

    That is the one wrong answer here: it invites a second dispatch on top of
    work items that may already exist.
    """
    with pytest.raises(ValueError, match="dispatch task did not report"):
        JiraDispatchResult.from_task_result(result)
