from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSecurityCenterAllAssetsAgentInstalled:
    def test_uninstalled_assets_fail(self):
        securitycenter_client = mock.MagicMock()
        securitycenter_client.audited_account = "1234567890"
        securitycenter_client.region = "cn-hangzhou"

        uninstalled = mock.MagicMock()
        uninstalled.instance_id = "i-1"
        uninstalled.instance_name = "asset1"
        uninstalled.region = "cn-hangzhou"
        uninstalled.os = "Linux"
        securitycenter_client.uninstalled_machines = [uninstalled]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.securitycenter.securitycenter_all_assets_agent_installed.securitycenter_all_assets_agent_installed.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_all_assets_agent_installed.securitycenter_all_assets_agent_installed import (
                securitycenter_all_assets_agent_installed,
            )

            check = securitycenter_all_assets_agent_installed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_all_assets_installed_passes(self):
        securitycenter_client = mock.MagicMock()
        securitycenter_client.audited_account = "1234567890"
        securitycenter_client.region = "cn-hangzhou"
        securitycenter_client.uninstalled_machines = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.securitycenter.securitycenter_all_assets_agent_installed.securitycenter_all_assets_agent_installed.securitycenter_client",
                new=securitycenter_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.securitycenter.securitycenter_all_assets_agent_installed.securitycenter_all_assets_agent_installed import (
                securitycenter_all_assets_agent_installed,
            )

            check = securitycenter_all_assets_agent_installed()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
