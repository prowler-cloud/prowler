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
            "EventId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
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

    def test_init_default_max_results(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._max_results == 50

    def test_init_custom_max_results(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session, max_results=10)
        assert timeline._max_results == 10

    def test_init_default_write_events_only(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._write_events_only is True

    def test_init_write_events_only_disabled(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session, write_events_only=False)
        assert timeline._write_events_only is False

    def test_get_resource_timeline_defaults_to_us_east_1(self, mock_session):
        """When no region is provided, should default to us-east-1 for global resources."""
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        timeline.get_resource_timeline(
            resource_uid="arn:aws:iam::123456789012:user/admin"
        )

        # Verify us-east-1 was used as the default region
        mock_session.client.assert_called_with("cloudtrail", region_name="us-east-1")

    def test_get_resource_timeline_missing_identifier_raises(self, mock_session):
        timeline = CloudTrailTimeline(session=mock_session)
        with pytest.raises(ValueError, match="Either resource_id or resource_uid"):
            timeline.get_resource_timeline(region="us-east-1")

    def test_get_resource_timeline_with_resource_id(
        self, mock_session, sample_cloudtrail_event
    ):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": [sample_cloudtrail_event]}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            region="us-east-1", resource_id="i-1234567890abcdef0"
        )

        assert len(result) == 1
        assert result[0]["event_name"] == "RunInstances"
        assert result[0]["actor"] == "admin"
        assert result[0]["source_ip_address"] == "203.0.113.1"

    def test_get_resource_timeline_with_resource_uid(
        self, mock_session, sample_cloudtrail_event
    ):
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": [sample_cloudtrail_event]}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            region="us-east-1",
            resource_uid="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
        )

        assert len(result) == 1
        assert result[0]["event_name"] == "RunInstances"

    def test_get_resource_timeline_prefers_uid_over_id(self, mock_session):
        """When both resource_id and resource_uid are provided, UID should be used."""
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        timeline.get_resource_timeline(
            region="us-east-1",
            resource_id="i-1234",
            resource_uid="arn:aws:ec2:us-east-1:123:instance/i-1234",
        )

        # Verify UID was used in the lookup
        call_args = mock_client.lookup_events.call_args
        lookup_attrs = call_args.kwargs["LookupAttributes"]
        assert (
            lookup_attrs[0]["AttributeValue"]
            == "arn:aws:ec2:us-east-1:123:instance/i-1234"
        )

    def test_get_resource_timeline_client_error(self, mock_session):
        mock_client = MagicMock()
        mock_client.lookup_events.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}},
            "LookupEvents",
        )
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        with pytest.raises(ClientError):
            timeline.get_resource_timeline(region="us-east-1", resource_id="i-1234")

    def test_get_resource_timeline_multiple_events(self, mock_session):
        events = [
            {
                "EventId": "event-1-id",
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
                "EventId": "event-2-id",
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
        mock_client.lookup_events.return_value = {"Events": events}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            region="us-east-1", resource_id="i-1234"
        )

        assert len(result) == 2
        assert result[0]["event_name"] == "RunInstances"
        assert result[1]["event_name"] == "StopInstances"

    def test_get_resource_timeline_uses_max_results(self, mock_session):
        """Verify MaxResults is passed to lookup_events."""
        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": []}
        mock_session.client.return_value = mock_client

        timeline = CloudTrailTimeline(session=mock_session, max_results=25)
        timeline.get_resource_timeline(region="us-east-1", resource_id="i-1234")

        # Verify MaxResults was passed to lookup_events
        call_args = mock_client.lookup_events.call_args
        assert call_args.kwargs["MaxResults"] == 25

    def test_get_resource_timeline_filters_read_only_events(self, mock_session):
        """Verify read-only events are filtered when write_events_only=True."""
        events = [
            {
                "EventId": "write-event-id",
                "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                "EventName": "CreateSecurityGroup",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
                ),
            },
            {
                "EventId": "read-event-id",
                "EventTime": datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
                "EventName": "DescribeSecurityGroups",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
                ),
            },
            {
                "EventId": "another-read-id",
                "EventTime": datetime(2024, 1, 15, 10, 32, 0, tzinfo=timezone.utc),
                "EventName": "GetSecurityGroupRules",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
                ),
            },
        ]

        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": events}
        mock_session.client.return_value = mock_client

        # Default: write_events_only=True
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline.get_resource_timeline(
            region="us-east-1", resource_id="sg-123"
        )

        # Only the write event should be returned
        assert len(result) == 1
        assert result[0]["event_name"] == "CreateSecurityGroup"

    def test_get_resource_timeline_includes_read_events_when_disabled(
        self, mock_session
    ):
        """Verify all events returned when write_events_only=False."""
        events = [
            {
                "EventId": "write-event-id",
                "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
                "EventName": "CreateSecurityGroup",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
                ),
            },
            {
                "EventId": "read-event-id",
                "EventTime": datetime(2024, 1, 15, 10, 31, 0, tzinfo=timezone.utc),
                "EventName": "DescribeSecurityGroups",
                "EventSource": "ec2.amazonaws.com",
                "CloudTrailEvent": json.dumps(
                    {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
                ),
            },
        ]

        mock_client = MagicMock()
        mock_client.lookup_events.return_value = {"Events": events}
        mock_session.client.return_value = mock_client

        # Disable filtering
        timeline = CloudTrailTimeline(session=mock_session, write_events_only=False)
        result = timeline.get_resource_timeline(
            region="us-east-1", resource_id="sg-123"
        )

        # All events should be returned
        assert len(result) == 2
        assert result[0]["event_name"] == "CreateSecurityGroup"
        assert result[1]["event_name"] == "DescribeSecurityGroups"


class TestExtractActor:
    def test_extract_actor_iam_user(self):
        user_identity = {
            "type": "IAMUser",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "userName": "alice",
        }
        assert CloudTrailTimeline._extract_actor(user_identity) == "alice"

    def test_extract_actor_assumed_role(self):
        user_identity = {
            "type": "AssumedRole",
            "arn": "arn:aws:sts::123456789012:assumed-role/MyRole/session-name",
        }
        assert CloudTrailTimeline._extract_actor(user_identity) == "MyRole"

    def test_extract_actor_root(self):
        user_identity = {"type": "Root", "arn": "arn:aws:iam::123456789012:root"}
        assert CloudTrailTimeline._extract_actor(user_identity) == "root"

    def test_extract_actor_service(self):
        user_identity = {
            "type": "AWSService",
            "invokedBy": "elasticloadbalancing.amazonaws.com",
        }
        assert (
            CloudTrailTimeline._extract_actor(user_identity)
            == "elasticloadbalancing.amazonaws.com"
        )

    def test_extract_actor_fallback_to_principal_id(self):
        user_identity = {"type": "Unknown", "principalId": "AROAEXAMPLEID:session"}
        assert (
            CloudTrailTimeline._extract_actor(user_identity) == "AROAEXAMPLEID:session"
        )

    def test_extract_actor_unknown(self):
        assert CloudTrailTimeline._extract_actor({}) == "Unknown"

    def test_extract_actor_federated_user(self):
        user_identity = {
            "type": "FederatedUser",
            "arn": "arn:aws:sts::123456789012:federated-user/developer",
        }
        assert CloudTrailTimeline._extract_actor(user_identity) == "developer"


class TestParseEvent:
    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.fixture
    def sample_cloudtrail_event(self):
        return {
            "EventId": "b2c3d4e5-f6a7-8901-bcde-f23456789012",
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
        assert result["actor"] == "admin"
        assert result["actor_uid"] == "arn:aws:iam::123456789012:user/admin"
        assert result["actor_type"] == "IAMUser"

    def test_parse_event_malformed_json(self, mock_session):
        event = {
            "EventId": "malformed-event-id",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": "not valid json",
        }
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._parse_event(event) is None

    def test_parse_event_with_error_fields(self, mock_session):
        event = {
            "EventId": "error-event-id",
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
            "EventId": "dict-event-id",
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
        assert result["actor"] == "admin"

    def test_parse_event_missing_event_id(self, mock_session):
        """Test parsing event without EventId returns None (event_id is required)."""
        event = {
            # Missing EventId
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {"userIdentity": {"type": "IAMUser", "userName": "admin"}}
            ),
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        # Should return None because event_id is required by TimelineEvent model
        assert result is None

    def test_parse_event_uses_request_data_and_response_data_fields(self, mock_session):
        """Test that parsed event uses request_data and response_data field names."""
        event = {
            "EventId": "field-names-test-id",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "CreateBucket",
            "EventSource": "s3.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {"type": "IAMUser", "userName": "admin"},
                    "requestParameters": {"bucketName": "my-bucket", "acl": "private"},
                    "responseElements": {
                        "location": "http://my-bucket.s3.amazonaws.com"
                    },
                }
            ),
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        assert result is not None
        # Verify field names are request_data/response_data (not request_parameters/response_elements)
        assert "request_data" in result
        assert "response_data" in result
        assert "request_parameters" not in result
        assert "response_elements" not in result
        # Verify the data is correctly mapped
        assert result["request_data"] == {"bucketName": "my-bucket", "acl": "private"}
        assert result["response_data"] == {
            "location": "http://my-bucket.s3.amazonaws.com"
        }

    def test_parse_event_missing_actor_type(self, mock_session):
        """Test parsing event where userIdentity has no type field."""
        event = {
            "EventId": "no-actor-type-id",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "RunInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {
                        # No "type" field
                        "arn": "arn:aws:iam::123456789012:user/admin",
                        "userName": "admin",
                    },
                    "sourceIPAddress": "203.0.113.1",
                }
            ),
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        assert result is not None
        assert result["event_name"] == "RunInstances"
        assert result["actor"] == "admin"
        # actor_type should be None when not present in userIdentity
        assert result["actor_type"] is None

    def test_parse_event_empty_request_response(self, mock_session):
        """Test parsing event with no requestParameters or responseElements."""
        event = {
            "EventId": "no-params-id",
            "EventTime": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "EventName": "DescribeInstances",
            "EventSource": "ec2.amazonaws.com",
            "CloudTrailEvent": json.dumps(
                {
                    "userIdentity": {"type": "IAMUser", "userName": "reader"},
                    # No requestParameters or responseElements
                }
            ),
        }
        timeline = CloudTrailTimeline(session=mock_session)
        result = timeline._parse_event(event)

        assert result is not None
        assert result["request_data"] is None
        assert result["response_data"] is None


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


class TestIsReadOnlyEvent:
    """Tests for _is_read_only_event method."""

    @pytest.fixture
    def mock_session(self):
        return MagicMock()

    @pytest.mark.parametrize(
        "event_name",
        [
            "DescribeSecurityGroups",
            "GetBucketPolicy",
            "ListBuckets",
            "HeadObject",
            "CheckAccessNotGranted",
            "LookupEvents",
            "SearchResources",
            "ScanOnDemand",
            "QueryObjects",
            "BatchGetItem",
            "SelectObjectContent",
        ],
    )
    def test_read_only_events_detected(self, mock_session, event_name):
        """Verify various read-only event prefixes are correctly identified."""
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._is_read_only_event(event_name) is True

    @pytest.mark.parametrize(
        "event_name",
        [
            "CreateSecurityGroup",
            "DeleteSecurityGroup",
            "ModifySecurityGroupRules",
            "PutBucketPolicy",
            "RunInstances",
            "TerminateInstances",
            "UpdateFunction",
            "AttachRolePolicy",
            "AuthorizeSecurityGroupIngress",
        ],
    )
    def test_write_events_not_filtered(self, mock_session, event_name):
        """Verify write events are not marked as read-only."""
        timeline = CloudTrailTimeline(session=mock_session)
        assert timeline._is_read_only_event(event_name) is False
