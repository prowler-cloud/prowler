"""Data models for CloudTrail timeline events."""

from datetime import datetime
from typing import Any, Optional

from pydantic.v1 import BaseModel


class TimelineEvent(BaseModel):
    """A CloudTrail event for the resource timeline.

    Matches the API TimelineEventSerializer contract.
    """

    event_time: datetime
    event_name: str
    event_source: str
    username: str
    user_identity_type: str
    source_ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_parameters: Optional[dict[str, Any]] = None
    response_elements: Optional[dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
