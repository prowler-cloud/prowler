"""Helpers for the duration and timestamp strings returned by the Cloud Identity Policy API."""

import re
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as date_parser

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)s$")

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
    """Render a duration string in days for use in a finding message."""
    seconds = parse_duration_seconds(value)
    if seconds is None:
        return "not configured"
    if seconds == 0:
        return "none"
    days = seconds / ONE_DAY_SECONDS
    if days.is_integer():
        return f"{int(days)} day(s)"
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


def is_enforcement_off(enforced_from: Optional[str]) -> bool:
    """Whether 2-Step Verification enforcement is switched off.

    Off is reported either as a missing value or as the zero-value Timestamp,
    which is compared as a moment in time so any spelling of the epoch matches.
    """
    if not enforced_from:
        return True
    parsed = _parse_timestamp(enforced_from)
    return parsed is not None and parsed <= _ENFORCEMENT_OFF_EPOCH


def is_enforcement_active(
    enforced_from: Optional[str], now: Optional[datetime] = None
) -> bool:
    """Whether an "On from <date>" enforcement timestamp has already started.

    Google accepts a future date, which means the policy is scheduled but not
    yet applied to anyone. An unreadable timestamp is treated as active so a
    format Prowler does not recognise cannot become a failure on its own; the
    caller still evaluates every other condition.
    """
    parsed = _parse_timestamp(enforced_from)
    if parsed is None:
        return True
    return parsed <= (now or datetime.now(timezone.utc))
