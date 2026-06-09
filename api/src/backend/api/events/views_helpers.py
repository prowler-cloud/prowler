"""Helpers for serializing resource timeline events into LLM-friendly formats.

The text renderer is a 1:1 markdown projection of what the JSON endpoint
returns: same events, same order, same fields. We do not infer sessions or
relationships between events — grouping is left to the consumer.
"""

from datetime import datetime, timezone
from typing import Any, Iterable

# Truncation thresholds for payload values. Strings longer than this are
# clipped with an ellipsis; lists/dicts larger than this collapse to a count
# placeholder. The goal is to bound a single event's token cost without
# losing the API call's identity.
MAX_STRING_LEN = 200
MAX_LIST_INLINE = 5
MAX_DICT_INLINE = 8


def serialize_events_as_text(
    events: Iterable[dict[str, Any]],
    resource: Any,
    lookback_days: int,
    write_events_only: bool,
) -> str:
    """Render resource events as a flat markdown list of what the API returns."""
    events = list(events)
    lines: list[str] = []

    lines.append("# Resource Events")
    lines.append(f"- Resource: {getattr(resource, 'uid', '')}")
    lines.append(f"- Region: {getattr(resource, 'region', '') or 'global'}")
    lines.append(f"- Lookback: {lookback_days} days")
    lines.append(f"- Write events only: {str(write_events_only).lower()}")
    lines.append(f"- Events: {len(events)}")
    lines.append("")

    if not events:
        lines.append("No events recorded in the lookback window.")
        return "\n".join(lines) + "\n"

    lines.append("## Events")
    lines.append("")

    for index, event in enumerate(events, 1):
        lines.extend(_format_event(index, event))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _format_event(index: int, event: dict[str, Any]) -> list[str]:
    when = _format_time(_event_time(event))
    name = event.get("event_name") or "Unknown"
    source = event.get("event_source") or "unknown"
    error_code = event.get("error_code")
    status = f"ERROR({error_code})" if error_code else "ok"

    lines = [f"### {index}. {name} at {when}"]
    lines.append(f"- Source: {source}")
    lines.append(f"- Status: {status}")

    if event.get("actor"):
        lines.append(f"- Actor: {event['actor']}")
    if event.get("actor_type"):
        lines.append(f"- Actor type: {event['actor_type']}")
    if event.get("actor_uid"):
        lines.append(f"- Actor ARN: {event['actor_uid']}")
    if event.get("source_ip_address"):
        lines.append(f"- Source IP: {event['source_ip_address']}")
    if event.get("user_agent"):
        lines.append(f"- User agent: {event['user_agent']}")

    request = _format_payload(event.get("request_data"))
    if request:
        lines.append(f"- Request: {request}")

    response = _format_payload(event.get("response_data"))
    if response:
        lines.append(f"- Response: {response}")

    if error_code and event.get("error_message"):
        lines.append(f"- Error: {event['error_message']}")

    if event.get("event_id"):
        lines.append(f"- Event ID: {event['event_id']}")

    return lines


def _format_payload(payload: Any) -> str:
    if not isinstance(payload, dict) or not payload:
        return ""
    return (
        "{" + ", ".join(f"{k}: {_summarize_value(v)}" for k, v in payload.items()) + "}"
    )


def _summarize_value(value: Any) -> str:
    if isinstance(value, str):
        if len(value) <= MAX_STRING_LEN:
            return f'"{value}"'
        return f'"{value[: MAX_STRING_LEN - 3]}..."'
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_LIST_INLINE:
            return f"[{len(value)} items]"
        return "[" + ", ".join(_summarize_value(v) for v in value) + "]"
    if isinstance(value, dict):
        if len(value) > MAX_DICT_INLINE:
            return f"{{{len(value)} keys}}"
        return (
            "{"
            + ", ".join(f"{k}: {_summarize_value(v)}" for k, v in value.items())
            + "}"
        )
    return str(value)


def _event_time(event: dict[str, Any]) -> datetime:
    value = event.get("event_time")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)
    return datetime.min.replace(tzinfo=timezone.utc)


def _format_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")
