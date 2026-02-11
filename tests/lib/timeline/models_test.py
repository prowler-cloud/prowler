from datetime import datetime, timezone

import pytest

from prowler.lib.timeline.models import TimelineEvent


class TestTimelineEvent:
    """Tests for TimelineEvent model."""

    def test_minimal_event(self):
        """Test creating an event with only required fields."""
        event = TimelineEvent(
            event_id="test-event-id-123",
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="CreateResource",
            event_source="service.example.com",
            actor="user@example.com",
            actor_type="User",
        )

        assert event.event_id == "test-event-id-123"
        assert event.event_time == datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        assert event.event_name == "CreateResource"
        assert event.event_source == "service.example.com"
        assert event.actor == "user@example.com"
        assert event.actor_type == "User"
        # Optional fields should be None
        assert event.actor_uid is None
        assert event.source_ip_address is None
        assert event.user_agent is None
        assert event.request_data is None
        assert event.response_data is None
        assert event.error_code is None
        assert event.error_message is None

    def test_full_event(self):
        """Test creating an event with all fields populated."""
        event = TimelineEvent(
            event_id="full-event-id-456",
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="ModifyResource",
            event_source="storage.example.com",
            actor="admin-role",
            actor_uid="arn:aws:sts::123456789012:assumed-role/admin-role/session",
            actor_type="AssumedRole",
            source_ip_address="192.168.1.100",
            user_agent="aws-cli/2.0.0",
            request_data={"bucket": "my-bucket", "acl": "private"},
            response_data={"status": "success"},
            error_code=None,
            error_message=None,
        )

        assert event.event_id == "full-event-id-456"
        assert (
            event.actor_uid
            == "arn:aws:sts::123456789012:assumed-role/admin-role/session"
        )
        assert event.source_ip_address == "192.168.1.100"
        assert event.user_agent == "aws-cli/2.0.0"
        assert event.request_data == {"bucket": "my-bucket", "acl": "private"}
        assert event.response_data == {"status": "success"}

    def test_error_event(self):
        """Test creating an event that represents a failed operation."""
        event = TimelineEvent(
            event_id="error-event-id-789",
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="DeleteResource",
            event_source="storage.example.com",
            actor="unauthorized-user",
            actor_type="User",
            error_code="AccessDenied",
            error_message="User does not have permission to delete this resource",
        )

        assert event.error_code == "AccessDenied"
        assert (
            event.error_message
            == "User does not have permission to delete this resource"
        )

    def test_event_to_dict(self):
        """Test that event can be serialized to dictionary."""
        event = TimelineEvent(
            event_id="dict-test-id",
            event_time=datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            event_name="CreateResource",
            event_source="service.example.com",
            actor="user@example.com",
            actor_type="User",
        )

        event_dict = event.dict()

        assert event_dict["event_id"] == "dict-test-id"
        assert event_dict["event_name"] == "CreateResource"
        assert event_dict["actor"] == "user@example.com"
        assert event_dict["actor_type"] == "User"

    def test_event_from_dict(self):
        """Test creating an event from a dictionary."""
        data = {
            "event_id": "from-dict-id",
            "event_time": datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc),
            "event_name": "UpdateResource",
            "event_source": "compute.example.com",
            "actor": "service-account",
            "actor_type": "ServiceAccount",
        }

        event = TimelineEvent(**data)

        assert event.event_id == "from-dict-id"
        assert event.event_name == "UpdateResource"
        assert event.actor == "service-account"
        assert event.actor_type == "ServiceAccount"

    def test_required_fields_validation(self):
        """Test that missing required fields raise validation error."""
        with pytest.raises(Exception):  # Pydantic validation error
            TimelineEvent(
                event_id="validation-test",
                event_time=datetime.now(timezone.utc),
                event_name="CreateResource",
                # Missing: event_source, actor, actor_type
            )

    def test_actor_types_are_flexible(self):
        """Test that actor_type accepts any string value (provider-agnostic)."""
        # AWS-style
        aws_event = TimelineEvent(
            event_id="aws-event-id",
            event_time=datetime.now(timezone.utc),
            event_name="CreateBucket",
            event_source="s3.amazonaws.com",
            actor="arn:aws:iam::123456789012:user/admin",
            actor_type="IAMUser",
        )
        assert aws_event.actor_type == "IAMUser"

        # Azure-style
        azure_event = TimelineEvent(
            event_id="azure-event-id",
            event_time=datetime.now(timezone.utc),
            event_name="CreateStorageAccount",
            event_source="Microsoft.Storage",
            actor="user@contoso.com",
            actor_type="User",
        )
        assert azure_event.actor_type == "User"

        # GCP-style
        gcp_event = TimelineEvent(
            event_id="gcp-event-id",
            event_time=datetime.now(timezone.utc),
            event_name="storage.buckets.create",
            event_source="storage.googleapis.com",
            actor="service-account@project.iam.gserviceaccount.com",
            actor_type="serviceAccount",
        )
        assert gcp_event.actor_type == "serviceAccount"
