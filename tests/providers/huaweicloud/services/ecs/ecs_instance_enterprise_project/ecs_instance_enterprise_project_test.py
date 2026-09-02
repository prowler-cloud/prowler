from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestEcsInstanceEnterpriseProject:
    def test_instance_with_enterprise_project_passes(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project import (
                ecs_instance_enterprise_project,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                enterprise_project_id="eps-123456",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_enterprise_project()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "eps-123456" in result[0].status_extended

    def test_instance_without_enterprise_project_fails(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project import (
                ecs_instance_enterprise_project,
            )
            from prowler.providers.huaweicloud.services.ecs.ecs_service import Instance

            instance = Instance(
                id="inst-1",
                name="web-server",
                region="la-south-2",
                status="ACTIVE",
                enterprise_project_id="",
            )
            ecs_client.instances = {instance.id: instance}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_enterprise_project()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "not assigned to an enterprise project" in result[0].status_extended

    def test_no_instances(self):
        ecs_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project.ecs_client",
                new=ecs_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.ecs.ecs_instance_enterprise_project.ecs_instance_enterprise_project import (
                ecs_instance_enterprise_project,
            )

            ecs_client.instances = {}
            ecs_client.audited_account = "123456789012"

            check = ecs_instance_enterprise_project()
            result = check.execute()

            assert len(result) == 0
