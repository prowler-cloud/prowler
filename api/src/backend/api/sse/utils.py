"""Channel-name convention shared by SSE publishers, consumers, and the
channel manager. The format is `<prefix>:<tenant_id>:<resource_id>`.
"""

from __future__ import annotations

import uuid

CHANNEL_SEPARATOR = ":"


def make_channel_name(
    prefix: str,
    tenant_id: str | uuid.UUID,
    resource_id: str | uuid.UUID,
) -> str:
    """Build the canonical channel name for a resource.

    Args:
        prefix: Feature-owned prefix (e.g. `"lighthouse-session"`).
        tenant_id: Tenant the resource belongs to.
        resource_id: Resource identifier within the tenant.

    Raises:
        ValueError: If any segment contains `CHANNEL_SEPARATOR`, which
            would break the `<prefix>:<tenant_id>:<resource_id>` contract
            and let a crafted name smuggle extra segments past the parser.
    """
    segments = (str(prefix), str(tenant_id), str(resource_id))
    if any(CHANNEL_SEPARATOR in segment for segment in segments):
        raise ValueError(
            f"Channel segments must not contain '{CHANNEL_SEPARATOR}': {segments!r}"
        )
    return CHANNEL_SEPARATOR.join(segments)


def tenant_id_from_channel(channel: str) -> uuid.UUID | None:
    """Return the tenant UUID embedded in *channel*, or `None` if
    *channel* does not follow the platform convention.

    A `None` result MUST be treated by callers as "not authorized" or
    a malformed channel cannot be safely read.
    """
    segments = channel.split(CHANNEL_SEPARATOR)
    if len(segments) != 3:
        # Reject non-canonical names
        return None
    try:
        return uuid.UUID(segments[1])
    except ValueError:
        return None
