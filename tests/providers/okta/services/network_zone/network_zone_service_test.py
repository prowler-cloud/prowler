import json
from types import SimpleNamespace
from unittest import mock

from pydantic import ValidationError

from prowler.providers.okta.models import OktaIdentityInfo
from prowler.providers.okta.services.network.network_zone_service import (
    NetworkZone,
    OktaNetworkZone,
    _next_after_cursor,
    _raw_zone_to_model,
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

        async def fake_list_network_zones(*_a, **_k):
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

        async def fake_list_network_zones(*_a, **kwargs):
            calls.append(kwargs.get("after"))
            if kwargs.get("after") is None:
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

        async def failing(*_a, **_k):
            return ([], _resp({}), Exception("forbidden"))

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = failing
            mocked_client_cls.return_value = mocked
            service = NetworkZone(provider)

        assert service.network_zones == {}

    def test_missing_network_zone_scope_skips_api_call(self):
        provider = set_mocked_okta_provider(
            identity=OktaIdentityInfo(
                org_domain="acme.okta.com",
                client_id="0oa1234567890abcdef",
                granted_scopes=["okta.policies.read", "okta.brands.read"],
            )
        )

        async def fail_if_called(*_a, **_k):
            raise AssertionError("list_network_zones should not be called")

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient"
        ) as mocked_client_cls:
            mocked = mock.MagicMock()
            mocked.list_network_zones = fail_if_called
            mocked_client_cls.return_value = mocked
            service = NetworkZone(provider)

        assert service.missing_scope["network_zones"] == "okta.networkZones.read"
        assert service.network_zones == {}


class Test_NetworkZone_service_sdk_validation_fallback:
    """Verifies the raw-JSON fallback for the Okta SDK Enhanced Dynamic
    Zone deserialization bug.

    The Okta Management API returns `asns.include` as a JSON array
    (typically `[]`) but the SDK's `EnhancedDynamicNetworkZoneAllOfAsnsInclude`
    is an object-shaped pydantic model — so listing zones raises
    ValidationError. Without a fallback the whole fetch crashes and
    every check FAILs as if no zones exist; with the fallback we parse
    the raw JSON and STIG evaluation continues.
    """

    @staticmethod
    def _trigger_real_validation_error() -> ValidationError:
        try:
            from okta.models.enhanced_dynamic_network_zone_all_of_asns_include import (  # noqa: E501
                EnhancedDynamicNetworkZoneAllOfAsnsInclude,
            )

            EnhancedDynamicNetworkZoneAllOfAsnsInclude.from_dict([])
        except ValidationError as ve:
            return ve
        raise AssertionError("Expected pydantic ValidationError from Okta SDK model")

    def _build_service_with_raw_payload(self, raw_zones_payload, response=None):
        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **_k):
            return ({"url": "/api/v1/zones"}, None)

        async def fake_raw_execute(_request):
            return (response, json.dumps(raw_zones_payload), None)

        sdk_mock = mock.MagicMock()
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            return NetworkZone(provider)

    def test_raw_fallback_projects_ip_and_enhanced_dynamic_zones(self):
        zones_payload = [
            {
                "id": "nzo-ip",
                "name": "Blocked IPs",
                "status": "ACTIVE",
                "type": "IP",
                "usage": "BLOCKLIST",
                "system": False,
                "gateways": [{"type": "CIDR", "value": "203.0.113.10/32"}],
                "proxies": [],
            },
            {
                "id": "nzo-enhanced",
                "name": "DefaultEnhancedDynamicZone",
                "status": "ACTIVE",
                "type": "DYNAMIC_V2",
                "usage": "BLOCKLIST",
                "system": True,
                "asns": {"include": [], "exclude": []},
                "locations": {"include": [], "exclude": []},
                "ipServiceCategories": [{"value": "ANONYMIZER"}],
            },
        ]

        service = self._build_service_with_raw_payload(zones_payload)

        assert set(service.network_zones.keys()) == {"nzo-ip", "nzo-enhanced"}
        ip_zone = service.network_zones["nzo-ip"]
        assert ip_zone.type == "IP"
        assert ip_zone.gateways == ["203.0.113.10/32"]
        enhanced = service.network_zones["nzo-enhanced"]
        assert enhanced.type == "DYNAMIC_V2"
        assert enhanced.system is True
        assert enhanced.ip_service_categories == ["ANONYMIZER"]
        assert enhanced.asns == []
        assert enhanced.locations == []

    def test_raw_fallback_handles_empty_payload(self):
        service = self._build_service_with_raw_payload([])
        assert service.network_zones == {}

    def test_raw_fallback_handles_executor_error(self):
        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **_k):
            return (None, Exception("network down"))

        sdk_mock = mock.MagicMock()
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = mock.AsyncMock()

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            service = NetworkZone(provider)

        assert service.network_zones == {}

    def test_raw_fallback_paginates_via_link_header(self):
        next_link = '<https://acme.okta.com/api/v1/zones?after=cursor-2>; rel="next"'
        page_1 = [
            {
                "id": "nzo-1",
                "name": "First",
                "status": "ACTIVE",
                "type": "IP",
                "usage": "BLOCKLIST",
            }
        ]
        page_2 = [
            {
                "id": "nzo-2",
                "name": "Second",
                "status": "ACTIVE",
                "type": "IP",
                "usage": "BLOCKLIST",
            }
        ]

        provider = set_mocked_okta_provider()
        ve = self._trigger_real_validation_error()
        execute_calls = []

        async def failing_list_network_zones(*_a, **_k):
            raise ve

        async def fake_raw_create(*_a, **kwargs):
            return ({"url": kwargs.get("url", "")}, None)

        async def fake_raw_execute(request):
            execute_calls.append(request)
            if len(execute_calls) == 1:
                return (
                    SimpleNamespace(headers={"link": next_link}),
                    json.dumps(page_1),
                    None,
                )
            return (SimpleNamespace(headers={}), json.dumps(page_2), None)

        sdk_mock = mock.MagicMock()
        sdk_mock.list_network_zones = failing_list_network_zones
        sdk_mock._request_executor.create_request = fake_raw_create
        sdk_mock._request_executor.execute = fake_raw_execute

        with mock.patch(
            "prowler.providers.okta.lib.service.service.OktaSDKClient",
            return_value=sdk_mock,
        ):
            service = NetworkZone(provider)

        assert len(execute_calls) == 2
        assert "after=cursor-2" in execute_calls[1]["url"]
        assert set(service.network_zones.keys()) == {"nzo-1", "nzo-2"}


class Test_raw_zone_to_model:
    def test_extracts_address_values_and_categories(self):
        zone = _raw_zone_to_model(
            {
                "id": "nzo-ip",
                "name": "IPs",
                "status": "ACTIVE",
                "type": "IP",
                "usage": "BLOCKLIST",
                "system": False,
                "gateways": [
                    {"type": "CIDR", "value": "203.0.113.0/24"},
                    {"type": "RANGE", "value": "198.51.100.5-198.51.100.10"},
                ],
                "proxies": [{"type": "CIDR", "value": "192.0.2.0/24"}],
                "ipServiceCategories": [
                    {"value": "ANONYMIZER"},
                    {"value": "TOR_ANONYMIZER"},
                ],
            }
        )
        assert zone.gateways == [
            "203.0.113.0/24",
            "198.51.100.5-198.51.100.10",
        ]
        assert zone.proxies == ["192.0.2.0/24"]
        assert zone.ip_service_categories == ["ANONYMIZER", "TOR_ANONYMIZER"]

    def test_collapses_non_list_asns_and_locations_to_empty(self):
        zone = _raw_zone_to_model(
            {
                "id": "nzo-enhanced",
                "name": "Enhanced",
                "type": "DYNAMIC_V2",
                "asns": {"include": [], "exclude": []},
                "locations": {"include": [], "exclude": []},
            }
        )
        assert zone.asns == []
        assert zone.locations == []
        assert isinstance(zone, OktaNetworkZone)

    def test_falls_back_name_to_id_when_missing(self):
        zone = _raw_zone_to_model({"id": "nzo-1"})
        assert zone.id == "nzo-1"
        assert zone.name == "nzo-1"
        assert zone.status == ""
        assert zone.system is False
