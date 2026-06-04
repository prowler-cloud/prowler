from types import SimpleNamespace
from unittest import mock

import pytest

from prowler.providers.okta.services.network.network_zone_service import (
    NETWORK_ZONES_READ_SCOPE,
    NetworkZone,
    OktaNetworkZone,
    _next_after_cursor,
)
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def _resp(headers: dict = None):
    return SimpleNamespace(headers=headers or {})


def _sdk_zone(
    zone_id: str,
    name: str,
    *,
    status: str = "ACTIVE",
    zone_type: str = "IP",
    usage: str = "BLOCKLIST",
    system: bool = False,
    gateways: list[str] = None,
    proxies: list[str] = None,
    ip_service_categories: list[str] = None,
):
    return SimpleNamespace(
        id=zone_id,
        name=name,
        status=status,
        type=zone_type,
        usage=usage,
        system=system,
        gateways=gateways or [],
        proxies=proxies or [],
        ip_service_categories=ip_service_categories or [],
    )


class Test_network_zone_pagination:
    def test_no_link_header_returns_none(self):
        assert _next_after_cursor(_resp({})) is None

    def test_extracts_next_after_cursor(self):
        link = (
            '<https://acme.okta.com/api/v1/zones?limit=20>; rel="self", '
            '<https://acme.okta.com/api/v1/zones?after=next-page>; rel="next"'
        )
        assert _next_after_cursor(_resp({"Link": link})) == "next-page"


class Test_NetworkZone_service:
    def test_fetches_ip_and_enhanced_dynamic_zones(self):
        provider = set_mocked_okta_provider()
        ip_zone = _sdk_zone(
            "nzo-ip",
            "Blocked IPs",
            gateways=["203.0.113.10/32"],
        )
        enhanced_zone = _sdk_zone(
            "nzo-enhanced",
            "DefaultEnhancedDynamicZone",
            zone_type="DYNAMIC_V2",
            system=True,
            ip_service_categories=["ANONYMIZER"],
        )

        async def fake_list_network_zones(after=None, limit=None):
            assert after is None
            assert limit == 200
            return ([ip_zone, enhanced_zone], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked

            service = NetworkZone(provider)

        assert set(service.network_zones.keys()) == {"nzo-ip", "nzo-enhanced"}
        assert isinstance(service.network_zones["nzo-ip"], OktaNetworkZone)
        assert service.network_zones["nzo-ip"].gateways == ["203.0.113.10/32"]
        assert service.network_zones["nzo-enhanced"].type == "DYNAMIC_V2"
        assert service.network_zones["nzo-enhanced"].ip_service_categories == [
            "ANONYMIZER"
        ]

    def test_paginates_network_zones(self):
        provider = set_mocked_okta_provider()
        page_1 = _sdk_zone("nzo-1", "First")
        page_2 = _sdk_zone("nzo-2", "Second")
        next_link = '<https://acme.okta.com/api/v1/zones?after=cursor-2>; rel="next"'
        calls = []

        async def fake_list_network_zones(after=None, limit=None):
            assert limit == 200
            calls.append(after)
            if after is None:
                return ([page_1], _resp({"link": next_link}), None)
            return ([page_2], _resp({}), None)

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = fake_list_network_zones
            mocked_client_cls.return_value = mocked
            service = NetworkZone(provider)

        assert calls == [None, "cursor-2"]
        assert set(service.network_zones.keys()) == {"nzo-1", "nzo-2"}

    def test_returns_empty_on_api_error(self):
        provider = set_mocked_okta_provider()

        async def failing(after=None, limit=None):
            assert after is None
            assert limit == 200
            return ([], _resp({}), Exception("forbidden"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = failing
            mocked_client_cls.return_value = mocked
            service = NetworkZone(provider)

        assert service.network_zones == {}

    @pytest.mark.parametrize("missing_scope", [NETWORK_ZONES_READ_SCOPE])
    def test_missing_scope_skips_network_zones_sdk_call(self, missing_scope):
        provider = set_mocked_okta_provider(scopes=[])

        async def forbidden_list_network_zones(after=None, limit=None):
            raise AssertionError("list_network_zones must not be called")

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = forbidden_list_network_zones
            mocked_client_cls.return_value = mocked
            service = NetworkZone(provider)

        assert service.missing_scopes == [missing_scope]
        assert service.network_zones == {}
