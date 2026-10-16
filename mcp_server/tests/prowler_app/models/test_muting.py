"""Tests for the muting (mutelist and mute rule) models.

`SimplifiedMuteRule.finding_count` is derived as `len(finding_uids)`, never read
directly from the API. `DetailedMuteRule.user_creator_id` distinguishes an absent
`created_by` relationship from one present with `data: null`.
"""

from prowler_mcp_server.prowler_app.models.muting import (
    DetailedMuteRule,
    MutelistResponse,
    MuteRulesListResponse,
    SimplifiedMuteRule,
)
from tests.helpers.jsonapi import jsonapi_document, jsonapi_resource

MUTE_RULE_ATTRIBUTES = {
    "name": "Ignore dev environment",
    "reason": "Accepted risk for the dev account",
    "enabled": True,
    "finding_uids": ["f1", "f2", "f3"],
}


def test_mutelist_response_reads_configuration():
    """The raw mutelist `configuration` object is carried through verbatim."""
    mutelist = MutelistResponse.from_api_response(
        jsonapi_resource(
            "mutelists",
            "m1",
            {"configuration": {"Accounts": {"*": {"Checks": {"*": {}}}}}},
        )
    )

    assert mutelist.id == "m1"
    assert mutelist.configuration == {"Accounts": {"*": {"Checks": {"*": {}}}}}


def test_mutelist_response_defaults_configuration_to_an_empty_dict():
    """A mutelist with no `configuration` attribute yields an empty dict."""
    mutelist = MutelistResponse.from_api_response(
        jsonapi_resource("mutelists", "m1", {})
    )

    assert mutelist.configuration == {}


def test_simplified_mute_rule_derives_finding_count_from_finding_uids():
    """finding_count is len(finding_uids), never read from the API directly."""
    rule = SimplifiedMuteRule.from_api_response(
        jsonapi_resource("mute-rules", "r1", MUTE_RULE_ATTRIBUTES)
    )

    assert rule.finding_count == 3


def test_simplified_mute_rule_finding_count_is_zero_when_no_findings_are_muted():
    """No `finding_uids` attribute derives a count of 0, not an error."""
    rule = SimplifiedMuteRule.from_api_response(
        jsonapi_resource(
            "mute-rules",
            "r1",
            {"name": "Empty rule", "reason": "none yet", "enabled": False},
        )
    )

    assert rule.finding_count == 0


def test_detailed_mute_rule_reads_the_finding_uids_and_creator():
    """The full finding_uids list is kept, and user_creator_id is lifted from the
    `created_by` relationship linkage."""
    resource = jsonapi_resource(
        "mute-rules",
        "r1",
        attributes=MUTE_RULE_ATTRIBUTES,
        relationships={
            "created_by": {"data": {"type": "users", "id": "u1"}},
        },
    )

    rule = DetailedMuteRule.from_api_response(resource)

    assert rule.finding_uids == ["f1", "f2", "f3"]
    assert rule.user_creator_id == "u1"


def test_detailed_mute_rule_creator_is_none_when_relationship_is_absent():
    """No `created_by` relationship at all leaves user_creator_id as None."""
    rule = DetailedMuteRule.from_api_response(
        jsonapi_resource("mute-rules", "r1", MUTE_RULE_ATTRIBUTES)
    )

    assert rule.user_creator_id is None


def test_detailed_mute_rule_creator_is_none_when_relationship_data_is_null():
    """`created_by` is present but its `data` is explicitly null -- distinct from
    the relationship being absent entirely, but the outcome (None) is the same
    since the code checks `if creator_data:` (truthy), not presence."""
    resource = jsonapi_resource(
        "mute-rules",
        "r1",
        attributes=MUTE_RULE_ATTRIBUTES,
        relationships={"created_by": {"data": None}},
    )

    rule = DetailedMuteRule.from_api_response(resource)

    assert rule.user_creator_id is None


def test_mute_rules_list_response_carries_pagination_metadata():
    """page/pages/count are read from `meta.pagination` when present."""
    response = jsonapi_document(
        data=[jsonapi_resource("mute-rules", "r1", MUTE_RULE_ATTRIBUTES)],
        meta={"pagination": {"page": 2, "pages": 5, "count": 42}},
    )

    result = MuteRulesListResponse.from_api_response(response)

    assert result.current_page == 2
    assert result.total_num_pages == 5
    assert result.total_num_mute_rules == 42
    assert result.mute_rules[0].name == "Ignore dev environment"


def test_mute_rules_list_response_defaults_pages_to_one_when_meta_is_missing():
    """Unlike roles/scans list responses (which default `pages` to 0), this one
    defaults to 1 -- a real inconsistency across the codebase, pinned here."""
    result = MuteRulesListResponse.from_api_response({"data": []})

    assert result.total_num_mute_rules == 0
    assert result.total_num_pages == 1
    assert result.current_page == 1
