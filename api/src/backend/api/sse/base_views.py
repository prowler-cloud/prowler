"""Base view class for SSE endpoints."""

from api.authentication import SSEAuthentication
from api.base_views import BaseRLSViewSet
from django_eventstream.renderers import SSEEventRenderer
from django_eventstream.views import events


class BaseSSEViewSet(BaseRLSViewSet):
    """Base class for platform SSE endpoints.

    Subclasses override method `get_channels` to declare the channel
    names the connection should subscribe to — the same way a regular
    DRF viewset overrides method `get_queryset`. The channel manager
    reads the result from `request.sse_channels`; there is no other
    coupling between platform and feature.
    """

    authentication_classes = [SSEAuthentication]
    # Pin the SSE renderer so content negotiation accepts the browser's
    # `Accept: text/event-stream`.
    renderer_classes = [SSEEventRenderer]

    def get_channels(self) -> set[str]:
        """Return the channels this connection subscribes to.

        Implementations MUST raise the relevant DRF exceptions
        (`NotAuthenticated`, `PermissionDenied`, `NotFound`) when
        authorization fails. Returning an empty set would surface as
        django-eventstream's "No channels specified" which masks the
        real cause.
        """
        raise NotImplementedError

    def get_queryset(self):
        # Most SSE viewsets only need `get_channels` and never call
        # `get_queryset` (the SSE list path bypasses serialization
        # entirely). Subclasses that perform their own queryset lookup
        # inside `get_channels` should override; the default raises
        # the same error a missing override on a ModelViewSet would.
        raise NotImplementedError

    def list(self, request, *_args, **kwargs):
        """Resolve channels under the regular DRF stack and stream."""
        request.sse_channels = self.get_channels()
        return events(request, **kwargs)
