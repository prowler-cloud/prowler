"""Channel manager that wires `django-eventstream` to platform SSE views."""

from __future__ import annotations

from django_eventstream.channelmanager import DefaultChannelManager

from api.sse.utils import tenant_id_from_channel


class SSEChannelManager(DefaultChannelManager):
    """Connect `django-eventstream` to the platform's SSE viewsets."""

    def get_channels_for_request(self, request, _view_kwargs):
        """Return the channels the viewset already computed on the request."""
        return getattr(request, "sse_channels", set())

    def can_read_channel(self, user, channel):
        """Re-verify tenant membership once the stream is established.

        The channel name embeds the tenant id; cross-tenant subscription
        is rejected here even if the URL-level check ever has a bug.
        Resource-level visibility was already enforced at connect.
        """
        if user is None or not user.is_authenticated:
            return False
        tenant_id = tenant_id_from_channel(channel)
        if tenant_id is None:
            return False
        return user.is_member_of_tenant(tenant_id)

    def is_channel_reliable(self, channel):
        """Clients refetch canonical state from REST on reconnect"""
        return False
