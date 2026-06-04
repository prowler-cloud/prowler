from unittest import mock

from prowler.providers.okta.services.network.network_zone_service import OktaNetworkZone
from tests.providers.okta.okta_fixtures import set_mocked_okta_provider


def build_network_zone_client(zones: dict = None, missing_scopes: list[str] = None):
    client = mock.MagicMock()
    client.network_zones = zones or {}
    client.missing_scopes = missing_scopes or []
    client.provider = set_mocked_okta_provider()
    return client


def network_zone(
    zone_id: str = "nzo-1",
    name: str = "BlockedIpZone",
    *,
    status: str = "ACTIVE",
    zone_type: str = "IP",
    usage: str = "BLOCKLIST",
    system: bool = False,
    gateways: list[str] = None,
    proxies: list[str] = None,
    ip_service_categories: list[str] = None,
):
    return OktaNetworkZone(
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
