from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class DummyVulnerability:
    def __init__(self, has_vulnerabilities: bool, count: int):
        self.has_vulnerabilities = has_vulnerabilities
        self.vulnerability_count = count


class TestEcsInstanceLatestOSPatchesApplied:
    def test_instance_with_vulnerabilities_fails(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.instances = []

        securitycenter_client = mock.MagicMock()
        securitycenter_client.instance_vulnerabilities = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied.ecs_client",
                new=ecs_client,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied import (
                ecs_instance_latest_os_patches_applied,
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
            securitycenter_client.instance_vulnerabilities = {
                "cn-hangzhou:i-1": DummyVulnerability(True, 5)
            }

            check = ecs_instance_latest_os_patches_applied()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_instance_no_vulnerabilities_passes(self):
        ecs_client = mock.MagicMock()
        ecs_client.audited_account = "1234567890"
        ecs_client.instances = []

        securitycenter_client = mock.MagicMock()
        securitycenter_client.instance_vulnerabilities = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied.ecs_client",
                new=ecs_client,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.ecs.ecs_instance_latest_os_patches_applied.ecs_instance_latest_os_patches_applied import (
                ecs_instance_latest_os_patches_applied,
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
            securitycenter_client.instance_vulnerabilities = {
                "cn-hangzhou:i-2": DummyVulnerability(False, 0)
            }

            check = ecs_instance_latest_os_patches_applied()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
