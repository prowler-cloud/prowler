from types import SimpleNamespace
from unittest import mock

from prowler.providers.huaweicloud.services.ecs.ecs_service import ECS, Instance
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


class TestECSService:
    def test_list_servers_parses_instances(self):
        server = SimpleNamespace(
            id="ecs-1",
            name="web-server",
            status="ACTIVE",
            flavor=None,
            access_i_pv4="1.2.3.4",
            security_groups=[SimpleNamespace(id="sg-1", name="web-sg")],
            enterprise_project_id="",
            created=None,
            key_name="my-keypair",
            metadata=None,
        )
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_servers_details.return_value = SimpleNamespace(
            count=1, servers=[server]
        )

        ecs = ECS(_provider_with_client(regional_client))

        assert len(ecs.instances) == 1
        instance = ecs.instances["ecs-1"]
        assert isinstance(instance, Instance)
        assert instance.name == "web-server"
        assert instance.region == REGION
        assert instance.public_ip == "1.2.3.4"
        assert instance.key_name == "my-keypair"
        assert instance.security_groups == {"sg-1": "web-sg"}

    def test_list_servers_empty(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_servers_details.return_value = SimpleNamespace(
            count=0, servers=[]
        )

        ecs = ECS(_provider_with_client(regional_client))

        assert ecs.instances == {}

    def test_list_servers_handles_sdk_error(self):
        regional_client = mock.MagicMock(region=REGION)
        regional_client.list_servers_details.side_effect = Exception("boom")

        ecs = ECS(_provider_with_client(regional_client))

        # Errors are logged and swallowed; no partial/garbage resources.
        assert ecs.instances == {}
