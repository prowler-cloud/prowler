"""Unit tests for api.events.views_helpers.

These tests exercise the text-renderer in isolation: no Django, no DRF, no DB.
The behavior under test is the markdown shape, payload sanitization, and
truncation rules.
"""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from api.events import views_helpers


@pytest.fixture
def resource():
    return SimpleNamespace(
        uid="arn:aws:s3:::acme-prod-data",
        region="us-east-1",
    )


def _event(**overrides):
    base = {
        "event_id": "evt-1",
        "event_time": datetime(2026, 5, 4, 16, 55, 1, tzinfo=timezone.utc),
        "event_name": "PutBucketPolicy",
        "event_source": "s3.amazonaws.com",
        "actor": "assumed-role/AdminRole/alice",
        "actor_uid": "arn:aws:sts::123:assumed-role/AdminRole/alice",
        "actor_type": "AssumedRole",
        "source_ip_address": "1.2.3.4",
        "user_agent": "aws-cli/2.15.30",
        "request_data": None,
        "response_data": None,
        "error_code": None,
        "error_message": None,
    }
    base.update(overrides)
    return base


class TestSerializeEventsAsTextHeader:
    def test_empty_events_renders_header_and_no_events_marker(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert text.startswith("# Resource Events\n")
        assert "- Resource: arn:aws:s3:::acme-prod-data" in text
        assert "- Region: us-east-1" in text
        assert "- Lookback: 90 days" in text
        assert "- Write events only: true" in text
        assert "- Events: 0" in text
        assert "No events recorded in the lookback window." in text
        # No "## Events" section when empty
        assert "## Events" not in text

    def test_missing_region_renders_global(self, resource):
        resource.region = ""

        text = views_helpers.serialize_events_as_text(
            events=[], resource=resource, lookback_days=7, write_events_only=False
        )

        assert "- Region: global" in text
        assert "- Write events only: false" in text
        assert "- Lookback: 7 days" in text

    def test_resource_without_uid_attribute_renders_blank(self):
        text = views_helpers.serialize_events_as_text(
            events=[],
            resource=SimpleNamespace(),
            lookback_days=1,
            write_events_only=True,
        )

        # getattr defaults to "" for both fields, no crash.
        assert "- Resource: \n" in text
        assert "- Region: global" in text


class TestSerializeEventsAsTextBody:
    def test_single_event_renders_all_present_fields(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event()],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "## Events" in text
        assert "### 1. PutBucketPolicy at 2026-05-04T16:55:01Z" in text
        assert "- Source: s3.amazonaws.com" in text
        assert "- Status: ok" in text
        assert "- Actor: assumed-role/AdminRole/alice" in text
        assert "- Actor type: AssumedRole" in text
        assert "- Actor ARN: arn:aws:sts::123:assumed-role/AdminRole/alice" in text
        assert "- Source IP: 1.2.3.4" in text
        assert "- User agent: aws-cli/2.15.30" in text
        assert "- Event ID: evt-1" in text

    def test_optional_fields_are_omitted_when_absent(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    actor_type=None,
                    actor_uid=None,
                    source_ip_address=None,
                    user_agent=None,
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Actor type:" not in text
        assert "- Actor ARN:" not in text
        assert "- Source IP:" not in text
        assert "- User agent:" not in text
        # Required field still rendered
        assert "- Actor: assumed-role/AdminRole/alice" in text

    def test_error_event_renders_error_code_and_message(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    error_code="AccessDenied",
                    error_message=(
                        "User: arn:aws:sts::123:assumed-role/AdminRole/alice "
                        "is not authorized to perform: s3:PutBucketAcl"
                    ),
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Status: ERROR(AccessDenied)" in text
        assert "- Error: User: arn:aws:sts::123:assumed-role/AdminRole/alice" in text

    def test_error_message_omitted_when_no_error_code(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    error_code=None,
                    error_message="orphaned message that should be ignored",
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Status: ok" in text
        assert "orphaned message" not in text

    def test_event_order_is_preserved_no_sorting(self, resource):
        # API returns CloudTrail events in its native order; the renderer
        # must NOT re-sort them.
        first = _event(
            event_id="newest",
            event_name="GetBucketPolicy",
            event_time=datetime(2026, 5, 4, 17, 2, 11, tzinfo=timezone.utc),
        )
        second = _event(
            event_id="middle",
            event_name="PutBucketAcl",
            event_time=datetime(2026, 5, 4, 16, 58, 33, tzinfo=timezone.utc),
        )
        third = _event(
            event_id="oldest",
            event_name="PutBucketPolicy",
            event_time=datetime(2026, 5, 4, 16, 55, 1, tzinfo=timezone.utc),
        )

        text = views_helpers.serialize_events_as_text(
            events=[first, second, third],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        idx_first = text.index("### 1. GetBucketPolicy")
        idx_second = text.index("### 2. PutBucketAcl")
        idx_third = text.index("### 3. PutBucketPolicy")
        assert idx_first < idx_second < idx_third

    def test_event_count_in_header_matches_body(self, resource):
        events = [_event(event_id=f"e{i}") for i in range(3)]
        text = views_helpers.serialize_events_as_text(
            events=events,
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Events: 3" in text
        assert text.count("### ") == 3


class TestPayloadFormatting:
    def test_request_data_renders_inline(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    request_data={
                        "bucketName": "acme-prod-data",
                        "encrypted": True,
                    }
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert '- Request: {bucketName: "acme-prod-data", encrypted: true}' in text

    def test_request_data_empty_dict_omits_line(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(request_data={})],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Request:" not in text

    def test_response_data_renders_when_present(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    response_data={"versionId": "abc123"},
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert '- Response: {versionId: "abc123"}' in text

    def test_long_strings_are_truncated(self, resource):
        long_policy = "x" * 500
        text = views_helpers.serialize_events_as_text(
            events=[_event(request_data={"policy": long_policy})],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        # 200-char threshold, with "..." marker on truncation
        assert "..." in text
        # The full 500-char value must NOT be present
        assert long_policy not in text

    def test_large_list_summarized_as_count(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(request_data={"tags": list(range(20))})],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "tags: [20 items]" in text

    def test_small_list_renders_inline(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(request_data={"ports": [80, 443]})],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "ports: [80, 443]" in text

    def test_large_dict_summarized_as_count(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    request_data={
                        "config": {f"key{i}": i for i in range(15)},
                    }
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "config: {15 keys}" in text

    def test_bool_and_none_values_lowercased(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(
                    request_data={
                        "publicAccess": True,
                        "encryption": False,
                        "kmsKey": None,
                    }
                )
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "publicAccess: true" in text
        assert "encryption: false" in text
        assert "kmsKey: null" in text

    def test_request_data_non_dict_is_ignored(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(request_data="not a dict")],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "- Request:" not in text


class TestTimeFormatting:
    def test_event_time_as_naive_datetime_is_treated_as_utc(self, resource):
        # Defensive: providers occasionally hand back naive datetimes;
        # they must be normalized rather than crashing the renderer.
        text = views_helpers.serialize_events_as_text(
            events=[
                _event(event_time=datetime(2026, 5, 4, 16, 55, 1)),
            ],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "### 1. PutBucketPolicy at 2026-05-04T16:55:01Z" in text

    def test_event_time_as_iso_string_is_parsed(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(event_time="2026-05-04T16:55:01Z")],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        assert "### 1. PutBucketPolicy at 2026-05-04T16:55:01Z" in text

    def test_unparseable_event_time_does_not_crash(self, resource):
        text = views_helpers.serialize_events_as_text(
            events=[_event(event_time="garbage")],
            resource=resource,
            lookback_days=90,
            write_events_only=True,
        )

        # Falls back to datetime.min — exact value isn't important, but
        # the renderer must not raise.
        assert "### 1. PutBucketPolicy at " in text
