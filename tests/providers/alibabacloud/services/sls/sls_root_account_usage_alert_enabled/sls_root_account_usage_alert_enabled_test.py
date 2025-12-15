from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSlsRootAccountUsageAlertEnabled:
    def test_alert_present_passes(self):
        sls_client = mock.MagicMock()
        sls_client.provider = set_mocked_alibabacloud_provider()
        sls_client.audited_account = "1234567890"
        alert = mock.MagicMock()
        alert.name = "root-usage"
        alert.arn = "arn:log:alert/root-usage"
        alert.region = "cn-hangzhou"
        alert.configuration = {
            "queryList": [
                {
                    "query": "ConsoleSignin | event.userIdentity.type: root-account",
                }
            ]
        }
        sls_client.alerts = [alert]
        sls_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=sls_client.provider,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_root_account_usage_alert_enabled.sls_root_account_usage_alert_enabled.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_root_account_usage_alert_enabled.sls_root_account_usage_alert_enabled import (
                sls_root_account_usage_alert_enabled,
            )

            check = sls_root_account_usage_alert_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_no_alert_fails(self):
        sls_client = mock.MagicMock()
        sls_client.provider = set_mocked_alibabacloud_provider()
        sls_client.audited_account = "1234567890"
        sls_client.alerts = []
        sls_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=sls_client.provider,
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_root_account_usage_alert_enabled.sls_root_account_usage_alert_enabled.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_root_account_usage_alert_enabled.sls_root_account_usage_alert_enabled import (
                sls_root_account_usage_alert_enabled,
            )

            check = sls_root_account_usage_alert_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
