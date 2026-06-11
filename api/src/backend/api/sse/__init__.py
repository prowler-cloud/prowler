"""Platform Server-Sent Events (SSE) infrastructure.

Wires `django-eventstream` into the API: a base viewset features
subclass to expose an SSE endpoint
(:class:`api.sse.base_views.BaseSSEViewSet`), the channel manager that
enforces the tenant gate (:class:`api.sse.channelmanager.SSEChannelManager`),
and the channel-name helpers (:func:`api.sse.utils.make_channel_name`).
"""

from api.sse.utils import make_channel_name
from api.sse.base_views import BaseSSEViewSet

__all__ = ["BaseSSEViewSet", "make_channel_name"]
