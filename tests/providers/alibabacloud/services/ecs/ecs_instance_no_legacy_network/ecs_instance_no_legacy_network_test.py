from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestEcsInstanceNoLegacyNetwork:
    def test_classic_network_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_no_legacy_network.ecs_instance_no_legacy_network.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_no_legacy_network.ecs_instance_no_legacy_network import (
                ecs_instance_no_legacy_network,
            )
            from prowler.providers.alibabacloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="i-1",
                name="i-1",
                region="cn-hangzhou",
                status="Running",
                instance_type="ecs.g6.large",
                network_type="classic",
                public_ip="",
                private_ip="10.0.0.1",
            )
            ecs_client.instances = [instance]

            check = ecs_instance_no_legacy_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_vpc_network_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_no_legacy_network.ecs_instance_no_legacy_network.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_no_legacy_network.ecs_instance_no_legacy_network import (
                ecs_instance_no_legacy_network,
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

            check = ecs_instance_no_legacy_network()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
