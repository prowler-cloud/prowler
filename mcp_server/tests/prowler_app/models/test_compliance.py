"""Tests for the compliance models.

`ComplianceFrameworkSummary` overrides `MinimalSerializerMixin`'s `_serialize`
(same method name wins via MRO) to unconditionally inject computed
`pass_percentage`/`fail_percentage` into every dump -- these must appear even
at zero requirements, where the division-by-zero guard kicks in.
"""

from prowler_mcp_server.prowler_app.models.compliance import (
    ComplianceFrameworksListResponse,
    ComplianceFrameworkSummary,
    ComplianceRequirement,
    ComplianceRequirementAttribute,
    ComplianceRequirementAttributesListResponse,
    ComplianceRequirementsListResponse,
)
from tests.helpers.jsonapi import jsonapi_document, jsonapi_resource

FRAMEWORK_ATTRIBUTES = {
    "id": "cis_1.5_aws",
    "framework": "CIS",
    "version": "1.5",
    "total_requirements": 100,
    "requirements_passed": 60,
    "requirements_failed": 30,
    "requirements_manual": 10,
}


def test_requirement_attribute_reads_the_double_nested_check_ids():
    """`check_ids` lives two levels deep: `data.attributes.attributes.check_ids`."""
    attribute = ComplianceRequirementAttribute.from_api_response(
        jsonapi_resource(
            "compliance-requirement-attributes",
            "req1",
            {
                "id": "1.1",
                "name": "Ensure MFA is enabled",
                "description": "Checks MFA is enabled for all users",
                "attributes": {"check_ids": ["iam_mfa_enabled"]},
            },
        )
    )

    assert attribute.name == "Ensure MFA is enabled"
    assert attribute.check_ids == ["iam_mfa_enabled"]


def test_requirement_attribute_id_prefers_the_nested_attributes_id():
    attribute = ComplianceRequirementAttribute.from_api_response(
        jsonapi_resource("compliance-requirement-attributes", "req1", {"id": "1.1"})
    )

    assert attribute.id == "1.1"


def test_requirement_attribute_id_falls_back_to_the_resource_id():
    """When attributes.id is absent, falls back to the top-level JSON:API id."""
    attribute = ComplianceRequirementAttribute.from_api_response(
        jsonapi_resource("compliance-requirement-attributes", "req1", {})
    )

    assert attribute.id == "req1"


def test_requirement_attribute_tolerates_missing_check_ids():
    attribute = ComplianceRequirementAttribute.from_api_response(
        jsonapi_resource("compliance-requirement-attributes", "req1", {"id": "1.1"})
    )

    assert attribute.check_ids == []


def test_requirement_attributes_list_response_counts_from_the_parsed_list():
    response = jsonapi_document(
        data=[
            jsonapi_resource("compliance-requirement-attributes", "r1", {"id": "1.1"}),
            jsonapi_resource("compliance-requirement-attributes", "r2", {"id": "1.2"}),
        ]
    )

    result = ComplianceRequirementAttributesListResponse.from_api_response(response)

    assert result.total_count == 2
    assert len(result.requirements) == 2


def test_framework_summary_reads_the_counters():
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource("compliance-overviews", "fw1", FRAMEWORK_ATTRIBUTES)
    )

    assert summary.compliance_id == "cis_1.5_aws"
    assert summary.framework == "CIS"
    assert summary.total_requirements == 100
    assert summary.requirements_passed == 60


def test_framework_summary_id_falls_back_to_the_resource_id():
    """compliance_id prefers attributes.id, falling back to the JSON:API id --
    distinct from the resource's own `id` field."""
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource(
            "compliance-overviews",
            "fw1",
            {"framework": "CIS", "version": "1.5"},
        )
    )

    assert summary.id == "fw1"
    assert summary.compliance_id == "fw1"


def test_framework_summary_computes_pass_and_fail_percentages():
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource("compliance-overviews", "fw1", FRAMEWORK_ATTRIBUTES)
    )

    assert summary.pass_percentage == 60.0
    assert summary.fail_percentage == 30.0


def test_framework_summary_rounds_percentages_to_one_decimal():
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource(
            "compliance-overviews",
            "fw1",
            {
                "framework": "CIS",
                "version": "1.5",
                "total_requirements": 3,
                "requirements_passed": 1,
                "requirements_failed": 1,
            },
        )
    )

    assert summary.pass_percentage == 33.3
    assert summary.fail_percentage == 33.3


def test_framework_summary_percentages_are_zero_when_there_are_no_requirements():
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource(
            "compliance-overviews", "fw1", {"framework": "CIS", "version": "1.5"}
        )
    )

    assert summary.pass_percentage == 0.0
    assert summary.fail_percentage == 0.0


def test_framework_summary_serialization_always_includes_the_computed_percentages():
    """The custom `_serialize` override injects both percentages into every dump,
    even when total_requirements is 0 -- unlike the mixin's normal exclusion of
    falsy/empty values, this bypasses it for these two computed keys."""
    summary = ComplianceFrameworkSummary.from_api_response(
        jsonapi_resource(
            "compliance-overviews", "fw1", {"framework": "CIS", "version": "1.5"}
        )
    )

    dumped = summary.model_dump()

    assert dumped["pass_percentage"] == 0.0
    assert dumped["fail_percentage"] == 0.0
    assert dumped["total_requirements"] == 0


def test_requirement_defaults_status_to_manual_when_missing():
    requirement = ComplianceRequirement.from_api_response(
        jsonapi_resource(
            "compliance-requirements", "r1", {"description": "Ensure MFA is enabled"}
        )
    )

    assert requirement.status == "MANUAL"


def test_requirement_reads_an_explicit_status():
    requirement = ComplianceRequirement.from_api_response(
        jsonapi_resource(
            "compliance-requirements",
            "r1",
            {"description": "Ensure MFA is enabled", "status": "FAIL"},
        )
    )

    assert requirement.status == "FAIL"


def test_frameworks_list_response_counts_from_the_parsed_list():
    response = jsonapi_document(
        data=[jsonapi_resource("compliance-overviews", "fw1", FRAMEWORK_ATTRIBUTES)]
    )

    result = ComplianceFrameworksListResponse.from_api_response(response)

    assert result.total_count == 1
    assert result.frameworks[0].framework == "CIS"


def test_requirements_list_response_counts_match_the_status_breakdown():
    """The invariant: passed + failed + manual always equals total_count, since
    all four are derived from the same parsed list."""
    response = jsonapi_document(
        data=[
            jsonapi_resource("compliance-requirements", "r1", {"status": "PASS"}),
            jsonapi_resource("compliance-requirements", "r2", {"status": "FAIL"}),
            jsonapi_resource(
                "compliance-requirements", "r3", {}
            ),  # No status -> MANUAL
        ]
    )

    result = ComplianceRequirementsListResponse.from_api_response(response)

    assert result.total_count == 3
    assert result.passed_count == 1
    assert result.failed_count == 1
    assert result.manual_count == 1
    assert (
        result.passed_count + result.failed_count + result.manual_count
        == result.total_count
    )
