from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSlsUnauthorizedApiCallsAlertEnabled:
    def test_alert_present_passes(self):
        sls_client = mock.MagicMock()
        sls_client.provider = set_mocked_alibabacloud_provider()
        sls_client.audited_account = "1234567890"
        alert = mock.MagicMock()
        alert.name = "unauth-api"
        alert.arn = "arn:log:alert/unauth"
        alert.region = "cn-hangzhou"
        alert.configuration = {
            "queryList": [{"query": "ApiCall | NoPermission"}],
        }
        sls_client.alerts = [alert]
        sls_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_unauthorized_api_calls_alert_enabled.sls_unauthorized_api_calls_alert_enabled.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_unauthorized_api_calls_alert_enabled.sls_unauthorized_api_calls_alert_enabled import (
                sls_unauthorized_api_calls_alert_enabled,
            )

            check = sls_unauthorized_api_calls_alert_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "configured for unauthorized API calls" in result[0].status_extended

    def test_no_alert_fails(self):
        sls_client = mock.MagicMock()
        sls_client.provider = set_mocked_alibabacloud_provider()
        sls_client.audited_account = "1234567890"
        sls_client.alerts = []
        sls_client.region = "cn-hangzhou"

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_unauthorized_api_calls_alert_enabled.sls_unauthorized_api_calls_alert_enabled.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_unauthorized_api_calls_alert_enabled.sls_unauthorized_api_calls_alert_enabled import (
                sls_unauthorized_api_calls_alert_enabled,
            )

            check = sls_unauthorized_api_calls_alert_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "No SLS Alert configured" in result[0].status_extended
