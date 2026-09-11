"""Tests for the scan models.

Two bug-shaped edge cases are pinned here rather than fixed (out of scope for a
test-coverage PR):
1. `SimplifiedScan.provider_id` is a non-Optional `str`, but `from_api_response`
   can pass `None` when the provider relationship is absent, raising a
   `ValidationError` at construction.
2. `DetailedScan.from_api_response` computes `task_id`/`processor_id` from
   relationships and passes them into the constructor, but neither is a
   declared field -- Pydantic's default `extra="ignore"` silently drops them.
"""

import pytest
from pydantic import ValidationError

from prowler_mcp_server.prowler_app.models.scans import (
    DetailedScan,
    ScanCreationResult,
    ScansListResponse,
    ScheduleCreationResult,
    SimplifiedScan,
)
from tests.helpers.jsonapi import (
    jsonapi_collection,
    jsonapi_relationship_one,
    jsonapi_resource,
)

SCAN_ATTRIBUTES = {
    "trigger": "manual",
    "state": "completed",
    "started_at": "2025-01-01T00:00:00Z",
    "completed_at": "2025-01-01T00:10:00Z",
}


def test_simplified_scan_reads_core_fields():
    """trigger/state come from attributes; provider_id is lifted out of the
    `provider` relationship linkage."""
    scan = SimplifiedScan.from_api_response(
        jsonapi_resource(
            "scans",
            "s1",
            attributes=SCAN_ATTRIBUTES,
            relationships={"provider": jsonapi_relationship_one("providers", "p1")},
        )
    )

    assert scan.id == "s1"
    assert scan.trigger == "manual"
    assert scan.state == "completed"
    assert scan.provider_id == "p1"


def test_simplified_scan_missing_provider_relationship_raises_validation_error():
    """provider_id is non-Optional str but from_api_response defaults to None
    when the relationship is absent -- pins a likely latent bug."""
    with pytest.raises(ValidationError):
        SimplifiedScan.from_api_response(
            jsonapi_resource("scans", "s1", attributes=SCAN_ATTRIBUTES)
        )


def test_detailed_scan_reads_operational_fields():
    """progress/duration/unique_resource_count are read from attributes."""
    resource = jsonapi_resource(
        "scans",
        "s1",
        attributes={
            **SCAN_ATTRIBUTES,
            "progress": 100,
            "duration": 120,
            "unique_resource_count": 42,
        },
        relationships={"provider": jsonapi_relationship_one("providers", "p1")},
    )

    scan = DetailedScan.from_api_response(resource)

    assert scan.progress == 100
    assert scan.duration == 120
    assert scan.unique_resource_count == 42


def test_detailed_scan_provider_id_defaults_to_empty_string_not_none():
    """Unlike SimplifiedScan.from_api_response (defaults to None, which fails
    validation), DetailedScan's own implementation defaults provider_id to ""
    when the relationship is absent -- a valid str, so no error here. This
    inconsistency between parent and child from_api_response is documented,
    not fixed."""
    scan = DetailedScan.from_api_response(
        jsonapi_resource("scans", "s1", attributes=SCAN_ATTRIBUTES)
    )

    assert scan.provider_id == ""


def test_detailed_scan_silently_drops_computed_task_and_processor_ids():
    """task_id/processor_id are computed from relationships but never declared
    as model fields -- Pydantic's default extra="ignore" drops them silently.
    This test proves they never surface, rather than relying on that silently."""
    resource = jsonapi_resource(
        "scans",
        "s1",
        attributes=SCAN_ATTRIBUTES,
        relationships={
            "provider": jsonapi_relationship_one("providers", "p1"),
            "task": jsonapi_relationship_one("tasks", "t1"),
            "processor": jsonapi_relationship_one("processors", "proc1"),
        },
    )

    scan = DetailedScan.from_api_response(resource)

    assert not hasattr(scan, "task_id")
    assert not hasattr(scan, "processor_id")
    dumped = scan.model_dump()
    assert "task_id" not in dumped
    assert "processor_id" not in dumped


def test_scans_list_response_carries_pagination_metadata():
    """page/pages/count are read from `meta.pagination` when present."""
    response = jsonapi_collection(
        [
            jsonapi_resource(
                "scans",
                "s1",
                attributes=SCAN_ATTRIBUTES,
                relationships={"provider": jsonapi_relationship_one("providers", "p1")},
            )
        ],
        page=1,
        pages=2,
        count=15,
    )

    result = ScansListResponse.from_api_response(response)

    assert result.total_num_scans == 15
    assert result.total_num_pages == 2
    assert result.scans[0].id == "s1"


def test_scans_list_response_defaults_pagination_when_meta_is_missing():
    """No `meta` at all defaults count/pages to 0 and page to 1 (unlike muting's
    list response, which defaults pages to 1)."""
    result = ScansListResponse.from_api_response({"data": []})

    assert result.total_num_scans == 0
    assert result.total_num_pages == 0
    assert result.current_page == 1


def test_scan_creation_result_is_constructed_directly_with_no_status_flag():
    """Built directly by the tool layer; carries no success/status flag by design."""
    scan = DetailedScan.from_api_response(
        jsonapi_resource(
            "scans",
            "s1",
            attributes=SCAN_ATTRIBUTES,
            relationships={"provider": jsonapi_relationship_one("providers", "p1")},
        )
    )

    result = ScanCreationResult(scan=scan, message="Scan started successfully")

    assert result.scan.id == "s1"
    assert "status" not in result.model_dump()


def test_schedule_creation_result_first_run_state_can_be_omitted():
    """first_run_state is optional; when None it is dropped from the dump."""
    result = ScheduleCreationResult(message="Schedule created successfully")

    assert result.first_run_state is None
    assert "first_run_state" not in result.model_dump()
