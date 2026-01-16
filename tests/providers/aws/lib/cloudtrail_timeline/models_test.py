"""Tests for CloudTrail timeline models."""

from datetime import datetime, timezone

import pytest

from prowler.providers.aws.lib.cloudtrail_timeline.models import TimelineEvent


class TestTimelineEvent:
    def test_timeline_event_required_fields(self):
        event = TimelineEvent(
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="RunInstances",
            event_source="ec2.amazonaws.com",
            username="admin",
            user_identity_type="IAMUser",
        )
        assert event.event_name == "RunInstances"
        assert event.username == "admin"
        assert event.source_ip_address is None

    def test_timeline_event_all_fields(self):
        event = TimelineEvent(
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="PutBucketPolicy",
            event_source="s3.amazonaws.com",
            username="admin",
            user_identity_type="IAMUser",
            source_ip_address="203.0.113.1",
            user_agent="aws-cli/2.0.0",
            request_parameters={"bucketName": "my-bucket"},
        )
        assert event.source_ip_address == "203.0.113.1"
        assert event.request_parameters == {"bucketName": "my-bucket"}

    def test_timeline_event_dict_serialization(self):
        event = TimelineEvent(
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="CreateSecurityGroup",
            event_source="ec2.amazonaws.com",
            username="developer",
            user_identity_type="AssumedRole",
        )
        result = event.dict()
        assert isinstance(result, dict)
        assert result["event_name"] == "CreateSecurityGroup"

    def test_timeline_event_with_error_fields(self):
        event = TimelineEvent(
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            username="developer",
            user_identity_type="IAMUser",
            error_code="AccessDenied",
            error_message="Access Denied",
        )
        assert event.error_code == "AccessDenied"
        assert event.error_message == "Access Denied"
