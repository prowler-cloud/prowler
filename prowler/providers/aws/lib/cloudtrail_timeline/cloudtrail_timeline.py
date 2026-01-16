"""CloudTrail timeline service for Prowler.

Queries AWS CloudTrail to retrieve timeline events for resources,
showing who performed actions and when.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from prowler.lib.logger import logger
from prowler.providers.aws.lib.cloudtrail_timeline.models import TimelineEvent


class CloudTrailTimeline:
    """Queries CloudTrail for resource timeline events.

    Args:
        session: boto3.Session for AWS API calls
        lookback_days: Number of days to look back (default 90, max 90 for Event History)
    """

    MAX_LOOKBACK_DAYS = 90

    def __init__(self, session, lookback_days: int = 90):
        self._session = session
        self._lookback_days = min(lookback_days, self.MAX_LOOKBACK_DAYS)
        self._clients: dict[str, Any] = {}

    def get_resource_timeline(
        self, resource_id: str, resource_arn: str, region: str
    ) -> list[dict[str, Any]]:
        """Get CloudTrail timeline events for a resource.

        Args:
            resource_id: AWS resource ID (e.g., sg-1234567890abcdef0)
            resource_arn: AWS resource ARN
            region: AWS region

        Returns:
            List of timeline event dictionaries, empty list if no events found
        """
        if not resource_id:
            logger.debug("CloudTrail timeline: skipping - no resource_id")
            return []

        if not region:
            logger.debug("CloudTrail timeline: skipping - no region")
            return []

        try:
            raw_events = self._lookup_events(resource_id, region)

            events = []
            for raw_event in raw_events:
                parsed = self._parse_event(raw_event)
                if parsed:
                    events.append(parsed)

            logger.debug(
                f"CloudTrail timeline: found {len(events)} events for {resource_id}"
            )
            return events

        except ClientError as e:
            logger.error(
                f"CloudTrail timeline error for {resource_id} in {region}: "
                f"{e.response['Error']['Code']} - {e.response['Error']['Message']}"
            )
            raise
        except Exception as e:
            logger.error(
                f"CloudTrail timeline unexpected error: "
                f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
            )
            return []

    def _get_client(self, region: str):
        """Get or create a CloudTrail client for the specified region."""
        if region not in self._clients:
            self._clients[region] = self._session.client(
                "cloudtrail", region_name=region
            )
        return self._clients[region]

    def _lookup_events(self, resource_id: str, region: str) -> list[dict[str, Any]]:
        """Query CloudTrail for events related to a specific resource."""
        client = self._get_client(region)
        start_time = datetime.now(timezone.utc) - timedelta(days=self._lookback_days)

        events = []
        paginator = client.get_paginator("lookup_events")

        for page in paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": resource_id}
            ],
            StartTime=start_time,
        ):
            events.extend(page.get("Events", []))

        return events

    def _parse_event(self, raw_event: dict[str, Any]) -> dict[str, Any] | None:
        """Parse a raw CloudTrail event into a TimelineEvent dictionary."""
        try:
            cloud_trail_event = raw_event.get("CloudTrailEvent", "{}")
            if isinstance(cloud_trail_event, str):
                details = json.loads(cloud_trail_event)
            else:
                details = cloud_trail_event

            user_identity = details.get("userIdentity", {})

            event = TimelineEvent(
                event_time=raw_event["EventTime"],
                event_name=raw_event.get("EventName", "Unknown"),
                event_source=raw_event.get("EventSource", "Unknown"),
                username=self._extract_username(user_identity),
                user_identity_type=user_identity.get("type", "Unknown"),
                source_ip_address=details.get("sourceIPAddress"),
                user_agent=details.get("userAgent"),
                request_parameters=details.get("requestParameters"),
                response_elements=details.get("responseElements"),
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
    def _extract_username(user_identity: dict[str, Any]) -> str:
        """Extract a human-readable username from CloudTrail userIdentity."""
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
