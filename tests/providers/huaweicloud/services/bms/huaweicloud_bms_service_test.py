from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.bms.bms_service import (
    BMS,
    BareMetalServer,
)
from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)

REGION = "la-south-2"


def _provider_with_client(regional_client):
    """Return a mocked provider whose regional client is the given mock."""
    provider = set_mocked_huaweicloud_provider(region=REGION)
    provider.generate_regional_clients = mock.MagicMock(
        return_value={REGION: regional_client}
    )
    return provider


class TestBMSService:
    def test_list_bare_metal_servers_parses_servers(self):
        server_with_public_ip = SimpleNamespace(
            id="bms-1",
            name="web-server",
            status="ACTIVE",
            addresses={
                "public": [
                    SimpleNamespace(os_ext_ips_type="floating", addr="1.2.3.4")
                ]
            },
            security_groups=[SimpleNamespace(id="sg-1", name="web-sg")],
        )
        server_internal = SimpleNamespace(
            id="bms-2",
            name="internal-server",
            status="ACTIVE",
            addresses=None,
            security_groups=[SimpleNamespace(id="sg-default", name="default")],
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_bare_metal_servers.return_value = SimpleNamespace(
            servers=[server_with_public_ip, server_internal]
        )

        bms = BMS(_provider_with_client(regional_client))

        assert len(bms.servers) == 2
        server1 = bms.servers["bms-1"]
        assert isinstance(server1, BareMetalServer)
        assert server1.name == "web-server"
        assert server1.region == REGION
        assert server1.status == "ACTIVE"
        assert server1.public_ip == "1.2.3.4"
        assert server1.security_groups == {"sg-1": "web-sg"}

        server2 = bms.servers["bms-2"]
        assert server2.public_ip == ""
        assert server2.security_groups == {"sg-default": "default"}

    def test_list_bare_metal_servers_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_bare_metal_servers.return_value = SimpleNamespace(
            servers=[]
        )

        bms = BMS(_provider_with_client(regional_client))

        assert bms.servers == {}

    def test_list_bare_metal_servers_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_bare_metal_servers.side_effect = Exception("boom")

        bms = BMS(_provider_with_client(regional_client))

        assert bms.servers == {}
