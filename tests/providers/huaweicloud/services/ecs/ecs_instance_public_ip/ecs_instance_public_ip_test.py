from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEcsInstancePublicIp:
    def test_instance_with_public_ip_fails(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                public_ip="1.2.3.4",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "1.2.3.4" in result[0].status_extended

    def test_instance_without_public_ip_passes(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="internal-server",
                region="la-south-2",
                status="ACTIVE",
                public_ip="",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_public_ip()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "does not have a public IP" in result[0].status_extended

    def test_no_instances(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_public_ip.ecs_instance_public_ip import (
                ecs_instance_public_ip,
            )

            ecs_client.instances = {}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_public_ip()
            result = check.execute()

            assert len(result) == 0
