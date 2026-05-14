from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestSlsLogstoreRetentionPeriod:
    def test_short_retention_fails(self):
        sls_client = mock.MagicMock()
        sls_client.audit_config = {"min_log_retention_days": 365}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import LogStore

            logstore = LogStore(
                name="short",
                project="proj",
                retention_forever=False,
                retention_days=90,
                region="cn-hangzhou",
                arn="arn:log:short",
            )
            sls_client.log_stores = [logstore]
            sls_client.provider = set_mocked_alibabacloud_provider()

            check = sls_logstore_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "less than" in result[0].status_extended

    def test_long_retention_passes(self):
        sls_client = mock.MagicMock()
        sls_client.audit_config = {"min_log_retention_days": 365}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
                new=sls_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import LogStore

            logstore = LogStore(
                name="long",
                project="proj",
                retention_forever=False,
                retention_days=400,
                region="cn-hangzhou",
                arn="arn:log:long",
            )
            sls_client.log_stores = [logstore]
            sls_client.provider = set_mocked_alibabacloud_provider()

            check = sls_logstore_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "retention set to 400 days" in result[0].status_extended
