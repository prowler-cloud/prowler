"""Unit tests for enrichment data models."""

from datetime import datetime, timedelta, timezone

from prowler.providers.aws.lib.cloudtrail_timeline.models import (
    EC2EventType,
    GeneralEventType,
    ResourceTimeline,
    TimelineEvent,
)


class TestTimelineEvent:
    """Tests for TimelineEvent model."""

    def test_timeline_event_creation(self):
        """Test creating a timeline event."""
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
            event_source="AWS CloudTrail",
            event_type=EC2EventType.SECURITY_GROUP_CREATED,
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-0abc123",
            principal="admin@company.com",
            message="Security group created by admin@company.com",
            event_details={"eventName": "CreateSecurityGroup"},
        )

        assert event.timestamp.year == 2025
        assert event.event_source == "AWS CloudTrail"
        assert event.event_type == EC2EventType.SECURITY_GROUP_CREATED
        assert event.resource_id == "sg-0abc123"
        assert event.principal == "admin@company.com"

    def test_timeline_event_to_dict(self):
        """Test converting timeline event to dictionary."""
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
            event_source="AWS CloudTrail",
            event_type=EC2EventType.INSTANCE_CREATED,
            resource_type="AWS::EC2::Instance",
            resource_id="i-0abc123",
            principal="deploy-role",
            message="Instance created",
        )

        event_dict = event.dict()

        assert event_dict["timestamp"] == datetime(
            2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc
        )
        assert event_dict["event_type"] == EC2EventType.INSTANCE_CREATED
        assert event_dict["resource_id"] == "i-0abc123"
        assert event_dict["principal"] == "deploy-role"

    def test_timeline_event_timezone_handling(self):
        """Test that timezone is enforced to UTC."""
        # Create event without timezone
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45),
            event_source="AWS CloudTrail",
            event_type=GeneralEventType.RESOURCE_CREATED,
            resource_type="AWS::EC2::Instance",
            resource_id="i-test",
            principal="test-user",
            message="Test event",
        )

        # Should be converted to UTC
        assert event.timestamp.tzinfo == timezone.utc


class TestResourceTimeline:
    """Tests for ResourceTimeline model."""

    def test_finding_enrichment_creation(self):
        """Test creating a finding enrichment."""
        events = [
            TimelineEvent(
                timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
                event_source="AWS CloudTrail",
                event_type=EC2EventType.SECURITY_GROUP_CREATED,
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="sg-0abc123",
                principal="admin@company.com",
                message="Security group created",
            ),
        ]

        enrichment = ResourceTimeline(
            timeline=events,
            created_by="admin@company.com",
            created_at=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
            last_modified_by="admin@company.com",
            last_modified_at=datetime(2025, 10, 15, 14, 24, 12, tzinfo=timezone.utc),
        )

        assert len(enrichment.timeline) == 1
        assert enrichment.created_by == "admin@company.com"
        assert enrichment.last_modified_by == "admin@company.com"

    def test_finding_enrichment_to_dict(self):
        """Test converting enrichment to dictionary."""
        enrichment = ResourceTimeline(
            created_by="test-user",
            created_at=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
        )

        enrichment_dict = enrichment.dict()

        assert enrichment_dict["created_by"] == "test-user"
        assert enrichment_dict["created_at"] == datetime(
            2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc
        )
        assert enrichment_dict["timeline"] == []

    def test_get_age_days(self):
        """Test calculating resource age in days."""
        # Create enrichment with created_at 10 days ago
        ten_days_ago = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=10)

        enrichment = ResourceTimeline(created_at=ten_days_ago)

        age_days = enrichment.get_age_days()
        assert age_days >= 10  # At least 10 days old

    def test_get_age_days_no_creation_date(self):
        """Test age calculation when no creation date available."""
        enrichment = ResourceTimeline()
        assert enrichment.get_age_days() is None

    def test_get_exposure_duration_days(self):
        """Test calculating exposure duration."""
        # Create enrichment modified 5 days ago
        five_days_ago = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        ) - timedelta(days=5)

        enrichment = ResourceTimeline(last_modified_at=five_days_ago)

        duration = enrichment.get_exposure_duration_days()
        assert duration >= 5  # At least 5 days

    def test_get_exposure_duration_days_no_modification_date(self):
        """Test exposure duration when no modification date available."""
        enrichment = ResourceTimeline()
        assert enrichment.get_exposure_duration_days() is None
