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

    def test_get_channels_for_request_reads_stashed_set(self):
        request = MagicMock()
        request.sse_channels = {"prefix:tenant:resource"}
        manager = SSEChannelManager()
        assert manager.get_channels_for_request(request, {}) == {
            "prefix:tenant:resource"
        }

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
