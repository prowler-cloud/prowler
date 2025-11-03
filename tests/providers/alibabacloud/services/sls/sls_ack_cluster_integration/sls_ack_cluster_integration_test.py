from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    set_mocked_alibabacloud_provider,
)


class Test_sls_ack_cluster_integration:
    def test_sls_ack_cluster_integration_pass(self):
        sls_client = mock.MagicMock
        sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_ack_cluster_integration.sls_ack_cluster_integration.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_ack_cluster_integration.sls_ack_cluster_integration import (
                sls_ack_cluster_integration,
            )

            check = sls_ack_cluster_integration()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sls-integration"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "SLS integration check" in result[0].status_extended
