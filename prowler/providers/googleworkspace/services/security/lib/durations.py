"""Helpers for the duration and timestamp values of the Cloud Identity security policies."""

import re
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as date_parser

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)s$")

ONE_HOUR_SECONDS = 3600
ONE_DAY_SECONDS = 86400
TWO_WEEKS_SECONDS = 1209600
ONE_YEAR_SECONDS = 31536000

# The API reports enforcement being OFF as the protobuf zero-value Timestamp
# rather than as a null or an empty string.
_ENFORCEMENT_OFF_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def parse_duration_seconds(value: Optional[str]) -> Optional[int]:
    """Return the seconds in a protobuf duration string such as "1209600s".

    Returns None when the value is missing or not a duration Prowler knows how
    to read, so callers can tell "not configured" apart from a real length.
    """
    if not value or not isinstance(value, str):
        return None
    match = _DURATION.match(value.strip())
    if not match:
        return None
    return int(float(match.group(1)))


def format_duration(value: Optional[str]) -> str:
    """Render a duration string in the largest whole unit, for a finding message."""
    seconds = parse_duration_seconds(value)
    if seconds is None:
        return "not configured"
    if seconds == 0:
        return "none"
    for unit_seconds, name in (
        (ONE_DAY_SECONDS, "day"),
        (ONE_HOUR_SECONDS, "hour"),
    ):
        units = seconds / unit_seconds
        if units.is_integer():
            return f"{int(units)} {name}(s)"
    return f"{seconds} second(s)"


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse an API timestamp, tolerating any fractional-second precision.

    protobuf emits up to nanosecond precision, which `datetime.fromisoformat`
    rejects before Python 3.11, so the shared dateutil parser is used instead.
    """
    if not value or not isinstance(value, str):
        return None
    try:
        parsed = date_parser.isoparse(value)
    except (ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def enforcement_issue(
    enforced_from: Optional[str],
    allow_scheduled: bool = False,
    now: Optional[datetime] = None,
) -> Optional[str]:
    """Return why 2-Step Verification enforcement is not in effect, or None.

    Google accepts a future start date, which means the policy is scheduled but
    not yet applied to anyone. CIS 4.1.1.2 accepts "On from <date>" explicitly
    while 4.1.1.1 and 4.1.1.3 ask for plain "On", hence `allow_scheduled`.
    """
    if not enforced_from:
        return "enforcement is not configured and defaults to OFF"
    parsed = _parse_timestamp(enforced_from)
    if parsed is None:
        return f"the enforcement start date '{enforced_from}' could not be read"
    if parsed <= _ENFORCEMENT_OFF_EPOCH:
        return "enforcement is set to OFF"
    if not allow_scheduled and parsed > (now or datetime.now(timezone.utc)):
        return f"enforcement does not start until {enforced_from}"
    return None
