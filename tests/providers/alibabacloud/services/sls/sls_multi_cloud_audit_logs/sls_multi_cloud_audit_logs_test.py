from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_sls_multi_cloud_audit_logs:
    def test_sls_multi_cloud_audit_logs_pass(self):
        sls_client = mock.MagicMock
        sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_multi_cloud_audit_logs.sls_multi_cloud_audit_logs.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_multi_cloud_audit_logs.sls_multi_cloud_audit_logs import (
                sls_multi_cloud_audit_logs,
            )

            check = sls_multi_cloud_audit_logs()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sls-integration"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "Multi-Cloud Audit Logs" in result[0].status_extended
