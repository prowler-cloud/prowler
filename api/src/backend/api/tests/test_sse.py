"""Tests for the platform SSE infrastructure (``api.sse``).

Cover the two security-critical platform pieces — the channel-name
convention (:mod:`api.sse.utils`) and the tenant gate enforced by
:class:`api.sse.channelmanager.SSEChannelManager`. The SSE authentication
class lives in :mod:`api.authentication` with the rest of the auth stack,
so its tests live in ``test_authentication.py``. Per-feature SSE endpoints
add their own tests on top of these.
"""

import uuid
from unittest.mock import MagicMock

import pytest
from django.http import StreamingHttpResponse
from rest_framework.test import APIRequestFactory, force_authenticate

from api.sse.base_views import BaseSSEViewSet
from api.sse.channelmanager import SSEChannelManager
from api.sse.utils import make_channel_name, tenant_id_from_channel


class TestMakeChannel:
    def test_round_trips_tenant_id(self):
        tenant_id = uuid.uuid4()
        channel = make_channel_name("lighthouse-session", tenant_id, uuid.uuid4())
        assert tenant_id_from_channel(channel) == tenant_id

    def test_accepts_str_arguments(self):
        tenant_id = uuid.uuid4()
        channel = make_channel_name("lighthouse-session", str(tenant_id), "resource-1")
        assert channel == f"lighthouse-session:{tenant_id}:resource-1"

    def test_prefix_with_hyphen_is_not_split(self):
        # Prefixes contain hyphens but never colons, so the tenant id is
        # always the second colon-separated segment.
        tenant_id = uuid.uuid4()
        channel = make_channel_name("a-long-hyphenated-prefix", tenant_id, "res")
        assert tenant_id_from_channel(channel) == tenant_id

    @pytest.mark.parametrize(
        "prefix, tenant_id, resource_id",
        [
            ("evil:prefix", uuid.uuid4(), "res"),
            ("prefix", uuid.uuid4(), "res:extra"),
            ("prefix", "tenant:smuggled", "res"),
        ],
    )
    def test_rejects_separator_injection(self, prefix, tenant_id, resource_id):
        # A colon in any segment would let a crafted name smuggle extra
        # segments past the parser, so construction must fail loudly.
        with pytest.raises(ValueError):
            make_channel_name(prefix, tenant_id, resource_id)


class TestTenantIdFromChannel:
    def test_returns_none_for_too_few_segments(self):
        assert tenant_id_from_channel("prefix:only") is None
        assert tenant_id_from_channel("garbage") is None

    def test_returns_none_for_too_many_segments(self):
        # A valid tenant UUID in position 1 must not authorize a
        # non-canonical name that carries extra segments.
        tenant_id = uuid.uuid4()
        assert tenant_id_from_channel(f"prefix:{tenant_id}:resource:extra") is None

    def test_returns_none_for_non_uuid_tenant_segment(self):
        assert tenant_id_from_channel("prefix:not-a-uuid:resource") is None

    def test_parses_valid_channel(self):
        tenant_id = uuid.uuid4()
        assert tenant_id_from_channel(f"prefix:{tenant_id}:resource") == tenant_id


@pytest.mark.django_db
class TestSSEChannelManager:
    def test_member_can_read_own_tenant_channel(
        self, create_test_user, tenants_fixture
    ):
        tenant = tenants_fixture[0]
        channel = make_channel_name("lighthouse-session", tenant.id, uuid.uuid4())
        assert SSEChannelManager().can_read_channel(create_test_user, channel)

    def test_non_member_cannot_read_other_tenant_channel(
        self, create_test_user, tenants_fixture
    ):
        # create_test_user is a member of tenant1 and tenant2 but not tenant3.
        foreign_tenant = tenants_fixture[2]
        channel = make_channel_name(
            "lighthouse-session", foreign_tenant.id, uuid.uuid4()
        )
        assert not SSEChannelManager().can_read_channel(create_test_user, channel)

    def test_anonymous_user_is_rejected(self, tenants_fixture):
        channel = make_channel_name(
            "lighthouse-session", tenants_fixture[0].id, uuid.uuid4()
        )
        assert not SSEChannelManager().can_read_channel(None, channel)

        anon = MagicMock(is_authenticated=False)
        assert not SSEChannelManager().can_read_channel(anon, channel)

    def test_malformed_channel_is_rejected(self, create_test_user, tenants_fixture):
        assert not SSEChannelManager().can_read_channel(create_test_user, "garbage")

    def test_get_channels_for_request_returns_active_tenant_channels(self):
        tenant_id = uuid.uuid4()
        own = make_channel_name("prefix", tenant_id, "resource")
        request = MagicMock()
        request.tenant_id = str(tenant_id)
        request.sse_channels = {own}
        assert SSEChannelManager().get_channels_for_request(request, {}) == {own}

    def test_get_channels_for_request_drops_other_tenant_channels(self):
        # Fail-closed: a channel for a tenant other than the active JWT
        # tenant is dropped before reaching django-eventstream, even if the
        # viewset mistakenly stashed it. This is the primary tenant gate that
        # binds authorization to request.tenant_id, not just membership.
        active_tenant = uuid.uuid4()
        own = make_channel_name("prefix", active_tenant, "resource")
        foreign = make_channel_name("prefix", uuid.uuid4(), "resource")
        request = MagicMock()
        request.tenant_id = str(active_tenant)
        request.sse_channels = {own, foreign}
        assert SSEChannelManager().get_channels_for_request(request, {}) == {own}

    def test_get_channels_for_request_drops_malformed_channels(self):
        request = MagicMock()
        request.tenant_id = str(uuid.uuid4())
        request.sse_channels = {"garbage", "prefix:not-a-uuid:resource"}
        assert SSEChannelManager().get_channels_for_request(request, {}) == set()

    def test_get_channels_for_request_without_tenant_returns_empty(self):
        # No active tenant on the request (auth/RLS never ran) → fail closed,
        # regardless of any channels stashed on it.
        request = MagicMock(spec=[])
        assert SSEChannelManager().get_channels_for_request(request, {}) == set()

    def test_get_channels_for_request_defaults_to_empty(self):
        # A request that never went through BaseSSEViewSet.list has no
        # sse_channels attribute; the manager must not raise.
        request = object()
        assert SSEChannelManager().get_channels_for_request(request, {}) == set()

    def test_channel_is_not_reliable(self):
        # v1 ships without server-side replay storage.
        assert (
            SSEChannelManager().is_channel_reliable("prefix:tenant:resource") is False
        )


@pytest.mark.django_db
class TestBaseSSEViewSet:
    """End-to-end check that the base viewset opens a stream.

    ``BaseSSEViewSet.list`` hands the DRF ``Request`` straight to
    django-eventstream's ``events()``, which is written for a plain
    Django request. This drives a real request through the full DRF
    stack (authentication, RLS, content negotiation, channel manager)
    and asserts the result is an SSE stream, so the DRF/Django request
    mismatch cannot regress silently.
    """

    def test_list_opens_event_stream(self, create_test_user, tenants_fixture):
        tenant = tenants_fixture[0]
        channel = make_channel_name("test-sse", tenant.id, uuid.uuid4())
        seen_tenant_ids = []

        class _StreamingSSEViewSet(BaseSSEViewSet):
            def get_channels(self):
                # Reached only after dispatch/initial ran, so the RLS
                # tenant context is already on the request.
                seen_tenant_ids.append(self.request.tenant_id)
                return {channel}

        request = APIRequestFactory().get("/api/v1/test-sse/stream")
        force_authenticate(
            request, user=create_test_user, token={"tenant_id": str(tenant.id)}
        )

        view = _StreamingSSEViewSet.as_view({"get": "list"})
        response = view(request)

        # A StreamingHttpResponse (not the plain HttpResponse used for SSE
        # error envelopes) means events() accepted the DRF request, the
        # channel manager handed it a non-empty channel set, and the
        # stream was opened end to end.
        assert isinstance(response, StreamingHttpResponse)
        assert response.status_code == 200
        assert response["Content-Type"] == "text/event-stream"
        assert seen_tenant_ids == [str(tenant.id)]
