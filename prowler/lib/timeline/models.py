"""Data models for timeline events."""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic.v1 import BaseModel


class TimelineEvent(BaseModel):
    """A timeline event representing a resource modification.

    Provider-agnostic model that can be used by any timeline implementation
    (AWS CloudTrail, Azure Activity Logs, GCP Audit Logs, etc.).
    """

    event_id: str
    event_time: datetime
    event_name: str
    event_source: str
    actor: str
    actor_type: str
    source_ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_parameters: Optional[Dict[str, Any]] = None
    response_elements: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
