"""Channel manager that wires `django-eventstream` to platform SSE views."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from django_eventstream.channelmanager import DefaultChannelManager
from rest_framework.request import Request

from api.sse.utils import tenant_id_from_channel

if TYPE_CHECKING:
    from api.models import User


class SSEChannelManager(DefaultChannelManager):
    """Connect `django-eventstream` to the platform's SSE viewsets."""

    def get_channels_for_request(self, request: Request, view_kwargs: dict) -> set[str]:
        """Return the request's channels scoped to the active JWT tenant.

        Args:
            request: The authenticated DRF request, carrying `tenant_id`
                (set by `BaseRLSViewSet`) and `sse_channels` (set by
                `BaseSSEViewSet.list`).
            view_kwargs: URL keyword arguments from django-eventstream;
                unused because channels are resolved on the request.

        Returns:
            The subset of `request.sse_channels` whose embedded tenant
            matches the active request tenant.
        """
        try:
            request_tenant_id = UUID(str(getattr(request, "tenant_id", None)))
        except (TypeError, ValueError):
            return set()
        return {
            channel
            for channel in getattr(request, "sse_channels", set())
            if tenant_id_from_channel(channel) == request_tenant_id
        }

    def can_read_channel(self, user: "User | None", channel: str) -> bool:
        """Re-verify tenant membership once the stream is established.

        Args:
            user: The connection's authenticated `User`, or `None` for an
                anonymous connection — django-eventstream passes `None`
                rather than an `AnonymousUser`.
            channel: The channel name being read, in the canonical
                `<prefix>:<tenant_id>:<resource_id>` format.

        Returns:
            `True` only when `user` is authenticated and a member of the
            tenant embedded in `channel`; `False` otherwise, including for
            anonymous connections and malformed channel names.
        """
        if user is None or not user.is_authenticated:
            return False
        tenant_id = tenant_id_from_channel(channel)
        if tenant_id is None:
            return False
        return user.is_member_of_tenant(tenant_id)

    def is_channel_reliable(self, channel: str) -> bool:
        """Report whether the channel keeps a server-side replay buffer.

        Args:
            channel: The channel name being queried.

        Returns:
            `False`, unconditionally. Replay storage is not configured
        """
        return False
