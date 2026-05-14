from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class DummyAgent:
    def __init__(self, installed: bool, status: str):
        self.agent_installed = installed
        self.agent_status = status


class TestEcsInstanceEndpointProtectionInstalled:
    def test_agent_missing_or_offline_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.instances = []

        securitycenter_client = mock.MagicMock()
        securitycenter_client.instance_agents = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed.ecs_client",
                new=ecs_client,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed import (
                ecs_instance_endpoint_protection_installed,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="i-1",
                name="i-1",
                region="cn-hangzhou",
                status="Running",
                instance_type="ecs.g6.large",
                network_type="vpc",
                public_ip="",
                private_ip="10.0.0.1",
            )
            ecs_client.instances = [instance]
            securitycenter_client.instance_agents = {
                "cn-hangzhou:i-1": DummyAgent(installed=False, status="offline")
            }

            check = ecs_instance_endpoint_protection_installed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_agent_installed_online_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.instances = []

        securitycenter_client = mock.MagicMock()
        securitycenter_client.instance_agents = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed.ecs_client",
                new=ecs_client,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_endpoint_protection_installed.ecs_instance_endpoint_protection_installed import (
                ecs_instance_endpoint_protection_installed,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="i-2",
                name="i-2",
                region="cn-hangzhou",
                status="Running",
                instance_type="ecs.g6.large",
                network_type="vpc",
                public_ip="",
                private_ip="10.0.0.2",
            )
            ecs_client.instances = [instance]
            securitycenter_client.instance_agents = {
                "cn-hangzhou:i-2": DummyAgent(installed=True, status="online")
            }

            check = ecs_instance_endpoint_protection_installed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
