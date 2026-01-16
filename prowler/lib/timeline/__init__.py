"""Timeline module for querying resource modification history."""

from prowler.lib.timeline.models import TimelineEvent
from prowler.lib.timeline.timeline import TimelineService

__all__ = ["TimelineEvent", "TimelineService"]
