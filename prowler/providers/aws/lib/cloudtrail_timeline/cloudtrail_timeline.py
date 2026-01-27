"""CloudTrail timeline service for AWS.

Queries AWS CloudTrail to retrieve timeline events for resources,
showing who performed actions and when.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from prowler.lib.logger import logger
from prowler.lib.timeline.models import TimelineEvent
from prowler.lib.timeline.timeline import TimelineService


class CloudTrailTimeline(TimelineService):
    """AWS CloudTrail implementation of TimelineService.

    Args:
        session: boto3.Session for AWS API calls
        lookback_days: Number of days to look back (default 90, max 90 for Event History)
        max_results: Maximum number of events to return
        write_events_only: If True, filter out read-only events (Describe*, Get*, List*, etc.)
    """

    MAX_LOOKBACK_DAYS = 90

    DEFAULT_MAX_RESULTS = 50  # Default page size for CloudTrail queries

    # Prefixes for read-only API operations that don't modify resources
    READ_ONLY_PREFIXES = (
        "Describe",
        "Get",
        "List",
        "Head",
        "Check",
        "Lookup",
        "Search",
        "Scan",
        "Query",
        "BatchGet",
        "Select",
    )

    def __init__(
        self,
        session,
        lookback_days: int = 90,
        max_results: Optional[int] = None,
        write_events_only: bool = True,
    ):
        self._session = session
        self._lookback_days = min(lookback_days, self.MAX_LOOKBACK_DAYS)
        self._max_results = max_results or self.DEFAULT_MAX_RESULTS
        self._write_events_only = write_events_only
        self._clients: Dict[str, Any] = {}

    DEFAULT_REGION = "us-east-1"  # Default for global resources in commercial partition

    def get_resource_timeline(
        self,
        region: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_uid: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get CloudTrail timeline events for a resource.

        Args:
            region: AWS region to query. Defaults to us-east-1 for global resources
                    (IAM, S3, Route53, etc.) in the commercial partition. Caller
                    should provide the correct region for regional resources.
            resource_id: AWS resource ID (e.g., sg-1234567890abcdef0)
            resource_uid: AWS resource ARN (unique identifier)

        Returns:
            List of timeline event dictionaries

        Raises:
            ValueError: If neither resource_id nor resource_uid is provided
            ClientError: If AWS API call fails
        """
        resource_identifier = resource_uid or resource_id
        if not resource_identifier:
            raise ValueError("Either resource_id or resource_uid must be provided")

        region = region or self.DEFAULT_REGION

        try:
            raw_events = self._lookup_events(resource_identifier, region)

            events = []
            for raw_event in raw_events:
                # Filter read-only events if write_events_only is enabled
                if self._write_events_only:
                    event_name = raw_event.get("EventName", "")
                    if self._is_read_only_event(event_name):
                        continue

                parsed = self._parse_event(raw_event)
                if parsed:
                    events.append(parsed)

            return events

        except ClientError as e:
            logger.error(
                f"CloudTrail timeline error for {resource_identifier} in {region}: "
                f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
            )
            raise
        except Exception as e:
            lineno = e.__traceback__.tb_lineno if e.__traceback__ else "?"
            logger.error(
                f"CloudTrail timeline unexpected error: "
                f"{e.__class__.__name__}[{lineno}]: {e}"
            )
            return []

    def _is_read_only_event(self, event_name: str) -> bool:
        """Check if an event is a read-only operation."""
        return event_name.startswith(self.READ_ONLY_PREFIXES)

    def _get_client(self, region: str):
        """Get or create a CloudTrail client for the specified region."""
        if region not in self._clients:
            self._clients[region] = self._session.client(
                "cloudtrail", region_name=region
            )
        return self._clients[region]

    def _lookup_events(
        self, resource_identifier: str, region: str
    ) -> List[Dict[str, Any]]:
        """Query CloudTrail for events related to a specific resource.

        Uses MaxResults to limit the number of events returned, preparing
        for API-level pagination. Currently returns up to max_results events
        from the first page only.
        """
        client = self._get_client(region)
        start_time = datetime.now(timezone.utc) - timedelta(days=self._lookback_days)

        # Use direct API call with MaxResults instead of paginator
        # This limits CloudTrail to return only max_results events
        response = client.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_identifier}
            ],
            StartTime=start_time,
            MaxResults=self._max_results,
        )

        return response.get("Events", [])

    def _parse_event(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse a raw CloudTrail event into a TimelineEvent dictionary."""
        try:
            cloud_trail_event = raw_event.get("CloudTrailEvent", "{}")
            if isinstance(cloud_trail_event, str):
                details = json.loads(cloud_trail_event)
            else:
                details = cloud_trail_event

            user_identity = details.get("userIdentity", {})

            event = TimelineEvent(
                event_id=raw_event.get("EventId"),
                event_time=raw_event["EventTime"],
                event_name=raw_event.get("EventName", "Unknown"),
                event_source=raw_event.get("EventSource", "Unknown"),
                actor=self._extract_actor(user_identity),
                actor_uid=user_identity.get("arn"),
                actor_type=user_identity.get("type"),
                source_ip_address=details.get("sourceIPAddress"),
                user_agent=details.get("userAgent"),
                request_data=details.get("requestParameters"),
                response_data=details.get("responseElements"),
                error_code=details.get("errorCode"),
                error_message=details.get("errorMessage"),
            )

            return event.dict()

        except Exception as e:
            logger.warning(
                f"CloudTrail timeline: failed to parse event: "
                f"{e.__class__.__name__}: {e}"
            )
            return None

    @staticmethod
    def _extract_actor(user_identity: Dict[str, Any]) -> str:
        """Extract a human-readable actor name from CloudTrail userIdentity."""
        # Try ARN first - most reliable
        if arn := user_identity.get("arn"):
            if "/" in arn:
                parts = arn.split("/")
                # For assumed-role, return the role name (second-to-last part)
                if "assumed-role" in arn and len(parts) >= 2:
                    return parts[-2]
                return parts[-1]
            return arn.split(":")[-1]

        # Fall back to userName
        if username := user_identity.get("userName"):
            return username

        # Fall back to principalId
        if principal_id := user_identity.get("principalId"):
            return principal_id

        # For service-invoked actions
        if invoking_service := user_identity.get("invokedBy"):
            return invoking_service

        return "Unknown"
