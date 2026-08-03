from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEcsInstanceNoDefaultSecurityGroup:
    def test_instance_with_default_security_group_fails(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group import (
                ecs_instance_no_default_security_group,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                security_groups={"sg-001": "default"},
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_no_default_security_group()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "uses the default security group" in result[0].status_extended

    def test_instance_without_default_security_group_passes(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group import (
                ecs_instance_no_default_security_group,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                security_groups={"sg-002": "custom-sg"},
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_no_default_security_group()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "does not use the default security group" in result[0].status_extended
            )

    def test_no_instances(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_no_default_security_group.ecs_instance_no_default_security_group import (
                ecs_instance_no_default_security_group,
            )

            ecs_client.instances = {}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_no_default_security_group()
            result = check.execute()

            assert len(result) == 0
