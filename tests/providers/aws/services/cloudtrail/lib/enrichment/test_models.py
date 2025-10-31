"""Unit tests for enrichment data models."""

from datetime import datetime, timezone

from prowler.providers.aws.services.cloudtrail.lib.enrichment.models import (
    FindingEnrichment,
    TimelineEvent,
    TimelineEventType,
)


class TestTimelineEvent:
    """Tests for TimelineEvent model."""

    def test_timeline_event_creation(self):
        """Test creating a timeline event."""
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
            event_source="AWS CloudTrail",
            event_type=TimelineEventType.SECURITY_GROUP_CREATED,
            resource_type="AWS::EC2::SecurityGroup",
            resource_id="sg-0abc123",
            principal="admin@company.com",
            message="Security group created by admin@company.com",
            event_details={"eventName": "CreateSecurityGroup"},
        )

        assert event.timestamp.year == 2025
        assert event.event_source == "AWS CloudTrail"
        assert event.event_type == TimelineEventType.SECURITY_GROUP_CREATED
        assert event.resource_id == "sg-0abc123"
        assert event.principal == "admin@company.com"

    def test_timeline_event_to_dict(self):
        """Test converting timeline event to dictionary."""
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
            event_source="AWS CloudTrail",
            event_type=TimelineEventType.INSTANCE_CREATED,
            resource_type="AWS::EC2::Instance",
            resource_id="i-0abc123",
            principal="deploy-role",
            message="Instance created",
        )

        event_dict = event.to_dict()

        assert event_dict["timestamp"] == "2025-10-15T14:23:45+00:00"
        assert event_dict["event_type"] == "instance_created"
        assert event_dict["resource_id"] == "i-0abc123"
        assert event_dict["principal"] == "deploy-role"

    def test_timeline_event_timezone_handling(self):
        """Test that timezone is enforced to UTC."""
        # Create event without timezone
        event = TimelineEvent(
            timestamp=datetime(2025, 10, 15, 14, 23, 45),
            event_source="AWS CloudTrail",
            event_type=TimelineEventType.RESOURCE_CREATED,
            resource_type="AWS::EC2::Instance",
            resource_id="i-test",
            principal="test-user",
            message="Test event",
        )

        # Should be converted to UTC
        assert event.timestamp.tzinfo == timezone.utc


class TestFindingEnrichment:
    """Tests for FindingEnrichment model."""

    def test_finding_enrichment_creation(self):
        """Test creating a finding enrichment."""
        events = [
            TimelineEvent(
                timestamp=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
                event_source="AWS CloudTrail",
                event_type=TimelineEventType.SECURITY_GROUP_CREATED,
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="sg-0abc123",
                principal="admin@company.com",
                message="Security group created",
            ),
        ]

        enrichment = FindingEnrichment(
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
        enrichment = FindingEnrichment(
            created_by="test-user",
            created_at=datetime(2025, 10, 15, 14, 23, 45, tzinfo=timezone.utc),
        )

        enrichment_dict = enrichment.to_dict()

        assert enrichment_dict["created_by"] == "test-user"
        assert enrichment_dict["created_at"] == "2025-10-15T14:23:45+00:00"
        assert enrichment_dict["timeline"] == []

    def test_get_age_days(self):
        """Test calculating resource age in days."""
        # Create enrichment with created_at 10 days ago
        ten_days_ago = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        ten_days_ago = ten_days_ago.replace(day=ten_days_ago.day - 10)

        enrichment = FindingEnrichment(created_at=ten_days_ago)

        age_days = enrichment.get_age_days()
        assert age_days >= 10  # At least 10 days old

    def test_get_age_days_no_creation_date(self):
        """Test age calculation when no creation date available."""
        enrichment = FindingEnrichment()
        assert enrichment.get_age_days() is None

    def test_get_exposure_duration_days(self):
        """Test calculating exposure duration."""
        # Create enrichment modified 5 days ago
        five_days_ago = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        five_days_ago = five_days_ago.replace(day=five_days_ago.day - 5)

        enrichment = FindingEnrichment(last_modified_at=five_days_ago)

        duration = enrichment.get_exposure_duration_days()
        assert duration >= 5  # At least 5 days

    def test_get_exposure_duration_days_no_modification_date(self):
        """Test exposure duration when no modification date available."""
        enrichment = FindingEnrichment()
        assert enrichment.get_exposure_duration_days() is None
