from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEcsInstanceVpcConfigured:
    def test_instance_with_vpc_passes(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured import (
                ecs_instance_vpc_configured,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                vpc_id="vpc-123456",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_vpc_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "vpc-123456" in result[0].status_extended

    def test_instance_without_vpc_fails(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured import (
                ecs_instance_vpc_configured,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                vpc_id="",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_vpc_configured()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not deployed within a VPC" in result[0].status_extended

    def test_no_instances(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_vpc_configured.ecs_instance_vpc_configured import (
                ecs_instance_vpc_configured,
            )

            ecs_client.instances = {}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_vpc_configured()
            result = check.execute()

            assert len(result) == 0
