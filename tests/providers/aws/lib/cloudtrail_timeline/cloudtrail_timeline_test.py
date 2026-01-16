"""Tests for CloudTrail timeline service."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from prowler.providers.aws.lib.cloudtrail_timeline.cloudtrail_timeline import (
    CloudTrailTimeline,
)


class TestCloudTrailTimeline:
    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def sample_cloudtrail_event(self):
        return {
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/admin",
                        "userName": "admin",
                    },
                    "sourceIPAddress": "203.0.113.1",
                    "userAgent": "aws-cli/2.0.0",
                    "requestParameters": {"instanceType": "t3.micro"},
                    "responseElements": {
                        "instancesSet": {"items": [{"instanceId": "i-1234"}]}
                    },
                }
            ),
        }

    def test_init_default_lookback(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._lookback_days == 90

    def test_init_custom_lookback(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session, lookback_days=30)
        assert timeline._lookback_days == 30

    def test_init_lookback_capped_at_max(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session, lookback_days=365)
        assert timeline._lookback_days == 90

    def test_get_resource_timeline_empty_resource_id(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            resource_id="", resource_arn="", region="us-east-1"
        )
        assert result == []

    def test_get_resource_timeline_empty_region(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            resource_id="i-1234567890abcdef0",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            region="",
        )
        assert result == []

    def test_get_resource_timeline_success(self, mock_session, sample_cloudtrail_event):
        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Events": [sample_cloudtrail_event]}]
        mock_client.get_paginator.return_value = mock_paginator
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            resource_id="i-1234567890abcdef0",
            resource_arn="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            region="us-east-1",
        )

        assert len(result) == 1
        assert result[0]["event_name"] == "RunInstances"
        assert result[0]["username"] == "admin"
        assert result[0]["source_ip_address"] == "203.0.113.1"

    def test_get_resource_timeline_client_error(self, mock_session):
        mock_client = MagicMock()
        mock_client.get_paginator.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "LookupEvents",
        )
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        with pytest.raises(ClientError):
            timeline.get_resource_timeline(
                resource_id="i-1234",
                resource_arn="arn:aws:ec2:us-east-1:123:instance/i-1234",
                region="us-east-1",
            )

    def test_get_resource_timeline_multiple_events(self, mock_session):
        events = [
            {
                "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                "EventName": "RunInstances",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "IAMUser",
                            "arn": "arn:aws:iam::123456789012:user/admin",
                        }
                    }
                ),
            },
            {
                "EventTime": datetime(2024, 1, 15, 11, 30, 0, tzinfo=timezone.utc),
                "EventName": "StopInstances",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {
                        "userIdentity": {
                            "type": "IAMUser",
                            "arn": "arn:aws:iam::123456789012:user/ops",
                        }
                    }
                ),
            },
        ]

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Events": events}]
        mock_client.get_paginator.return_value = mock_paginator
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            resource_id="i-1234",
            resource_arn="arn:aws:ec2:us-east-1:123:instance/i-1234",
            region="us-east-1",
        )

        assert len(result) == 2
        assert result[0]["event_name"] == "RunInstances"
        assert result[1]["event_name"] == "StopInstances"


class TestExtractUsername:
    def test_extract_username_iam_user(self):
        user_identity = {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
        }
        assert CloudTrailTimeline._extract_username(user_identity) == "alice"

    def test_extract_username_assumed_role(self):
        user_identity = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
        }
        assert CloudTrailTimeline._extract_username(user_identity) == "MyRole"

    def test_extract_username_root(self):
        user_identity = {"type": "Root", "arn": "arn:aws:iam::123456789012:root"}
        assert CloudTrailTimeline._extract_username(user_identity) == "root"

    def test_extract_username_service(self):
        user_identity = {
            "type": "AWSService",
            "invokedBy": "elasticloadbalancing.amazonaws.com",
        }
        assert (
            CloudTrailTimeline._extract_username(user_identity)
            == "elasticloadbalancing.amazonaws.com"
        )

    def test_extract_username_fallback_to_principal_id(self):
        user_identity = {"type": "Unknown", "principalId": "AROAEXAMPLEID:session"}
        assert (
            CloudTrailTimeline._extract_username(user_identity)
            == "AROAEXAMPLEID:session"
        )

    def test_extract_username_unknown(self):
        assert CloudTrailTimeline._extract_username({}) == "Unknown"

    def test_extract_username_federated_user(self):
        user_identity = {
            "type": "FederatedUser",
            "arn": "arn:aws:sts::123456789012:federated-user/developer",
        }
        assert CloudTrailTimeline._extract_username(user_identity) == "developer"


class TestParseEvent:
    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def sample_cloudtrail_event(self):
        return {
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {
                        "type": "IAMUser",
                        "arn": "arn:aws:iam::123456789012:user/admin",
                        "userName": "admin",
                    },
                    "sourceIPAddress": "203.0.113.1",
                    "userAgent": "aws-cli/2.0.0",
                    "requestParameters": {"instanceType": "t3.micro"},
                    "responseElements": {
                        "instancesSet": {"items": [{"instanceId": "i-1234"}]}
                    },
                }
            ),
        }

    def test_parse_event_success(self, mock_session, sample_cloudtrail_event):
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(sample_cloudtrail_event)

        assert result is not None
        assert result["event_name"] == "RunInstances"
        assert result["event_source"] == "ec2.amazonaws.com"
        assert result["username"] == "admin"
        assert result["user_identity_type"] == "IAMUser"

    def test_parse_event_malformed_json(self, mock_session):
        event = {
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": "not valid json",
        }
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._parse_event(event) is None

    def test_parse_event_with_error_fields(self, mock_session):
        event = {
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "CreateBucket",
            "EventSource": "s3.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {"type": "IAMUser", "userName": "developer"},
                    "errorCode": "AccessDenied",
                    "errorMessage": "Access Denied",
                }
            ),
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        assert result is not None
        assert result["error_code"] == "AccessDenied"
        assert result["error_message"] == "Access Denied"

    def test_parse_event_dict_cloud_trail_event(self, mock_session):
        """Test parsing when CloudTrailEvent is already a dict (not JSON string)."""
        event = {
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": {
                "userIdentity": {"type": "IAMUser", "userName": "admin"},
            },
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        assert result is not None
        assert result["event_name"] == "RunInstances"
        assert result["username"] == "admin"


class TestClientCaching:
    def test_client_cached_per_region(self):
        mock_session = MagicMock()
        mock_client = MagicMock()
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)

        # Get client twice for same region
        client1 = timeline._get_client("us-east-1")
        client2 = timeline._get_client("us-east-1")

        # Should only create client once
        assert mock_session.client.call_count == 1
        assert client1 is client2

    def test_different_clients_per_region(self):
        mock_session = MagicMock()

        timeline = CloudTrailTimeline(session=mock_session)

        timeline._get_client("us-east-1")
        timeline._get_client("eu-west-1")

        # Should create client for each region
        assert mock_session.client.call_count == 2
