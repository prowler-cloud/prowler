"""Abstract base class for timeline services."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class TimelineService(ABC):
    """Abstract base class for provider-specific timeline implementations.

    Subclasses should implement the get_resource_timeline method to query
    their provider's audit/activity log service (e.g., AWS CloudTrail,
    Azure Activity Logs, GCP Audit Logs).
    """

    @abstractmethod
    def get_resource_timeline(
        self,
        region: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_uid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get timeline events for a resource.

        Args:
            region: Region/location where the resource exists. Implementations
                    may provide a sensible default for global/regionless resources.
            resource_id: Provider-specific resource ID (e.g., bucket name, instance ID)
            resource_uid: Provider-specific unique identifier (e.g., AWS ARN, Azure Resource ID)

        Returns:
            List of timeline event dictionaries

        Raises:
            ValueError: If neither resource_id nor resource_uid is provided
        """
        raise NotImplementedError
