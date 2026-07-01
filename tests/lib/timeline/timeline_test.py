"""Tests for prowler.lib.timeline.timeline module."""

from typing import Any, Dict, List, Optional

import pytest

from prowler.lib.timeline.timeline import TimelineService


class ConcreteTimelineService(TimelineService):
    """Concrete implementation for testing the abstract base class."""

    def __init__(self, mock_events: Optional[List[Dict[str, Any]]] = None):
        self.mock_events = mock_events or []
        self.last_call_args = None

    def get_resource_timeline(
        self,
        region: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_uid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return mock events for testing."""
        if not resource_id and not resource_uid:
            raise ValueError("Either resource_id or resource_uid must be provided")

        self.last_call_args = {
            "region": region,
            "resource_id": resource_id,
            "resource_uid": resource_uid,
        }
        return self.mock_events


class TestTimelineServiceAbstract:
    """Tests for TimelineService abstract base class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that TimelineService cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            TimelineService()

        assert "abstract" in str(exc_info.value).lower()

    def test_concrete_implementation_can_be_instantiated(self):
        """Test that a concrete implementation can be instantiated."""
        service = ConcreteTimelineService()
        assert service is not None

    def test_get_resource_timeline_with_resource_id(self):
        """Test calling get_resource_timeline with resource_id."""
        service = ConcreteTimelineService(mock_events=[{"event": "test"}])

        result = service.get_resource_timeline(
            region="us-east-1", resource_id="res-123"
        )

        assert result == [{"event": "test"}]
        assert service.last_call_args["region"] == "us-east-1"
        assert service.last_call_args["resource_id"] == "res-123"
        assert service.last_call_args["resource_uid"] is None

    def test_get_resource_timeline_with_resource_uid(self):
        """Test calling get_resource_timeline with resource_uid."""
        service = ConcreteTimelineService(mock_events=[{"event": "test"}])

        result = service.get_resource_timeline(
            region="eu-west-1",
            resource_uid="arn:aws:s3:::my-bucket",
        )

        assert result == [{"event": "test"}]
        assert service.last_call_args["region"] == "eu-west-1"
        assert service.last_call_args["resource_id"] is None
        assert service.last_call_args["resource_uid"] == "arn:aws:s3:::my-bucket"

    def test_get_resource_timeline_with_both_identifiers(self):
        """Test calling get_resource_timeline with both resource_id and resource_uid."""
        service = ConcreteTimelineService(mock_events=[])

        service.get_resource_timeline(
            region="ap-south-1",
            resource_id="res-123",
            resource_uid="arn:aws:ec2:ap-south-1:123456789012:instance/i-12345",
        )

        assert service.last_call_args["resource_id"] == "res-123"
        assert (
            service.last_call_args["resource_uid"]
            == "arn:aws:ec2:ap-south-1:123456789012:instance/i-12345"
        )

    def test_get_resource_timeline_missing_identifiers_raises(self):
        """Test that missing both identifiers raises ValueError."""
        service = ConcreteTimelineService()

        with pytest.raises(ValueError) as exc_info:
            service.get_resource_timeline(region="us-west-2")

        assert "resource_id" in str(exc_info.value) or "resource_uid" in str(
            exc_info.value
        )

    def test_return_type_is_list_of_dicts(self):
        """Test that get_resource_timeline returns list of dicts (not TimelineEvent)."""
        # The abstract interface returns list[dict] to allow flexibility
        # Concrete implementations convert to TimelineEvent as needed
        mock_events = [
            {"event_name": "CreateBucket", "actor": "user1"},
            {"event_name": "PutBucketPolicy", "actor": "user2"},
        ]
        service = ConcreteTimelineService(mock_events=mock_events)

        result = service.get_resource_timeline(
            region="us-east-1", resource_id="my-bucket"
        )

        assert isinstance(result, list)
        assert all(isinstance(event, dict) for event in result)


class TestTimelineServiceInheritance:
    """Tests for proper inheritance of TimelineService."""

    def test_is_abstract_base_class(self):
        """Test that TimelineService is an ABC."""
        from abc import ABC

        assert issubclass(TimelineService, ABC)

    def test_get_resource_timeline_is_abstract(self):
        """Test that get_resource_timeline is an abstract method."""

        method = getattr(TimelineService, "get_resource_timeline")
        assert getattr(method, "__isabstractmethod__", False)

    def test_subclass_must_implement_abstract_method(self):
        """Test that subclass without implementation cannot be instantiated."""

        class IncompleteService(TimelineService):
            """Subclass that doesn't implement abstract methods."""

        with pytest.raises(TypeError):
            IncompleteService()
