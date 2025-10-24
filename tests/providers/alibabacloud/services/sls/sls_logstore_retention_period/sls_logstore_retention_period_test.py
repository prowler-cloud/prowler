from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_sls_logstore_retention_period:
    def test_no_logstores(self):
        sls_client = mock.MagicMock
        sls_client.logstores = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )

            check = sls_logstore_retention_period()
            result = check.execute()
            assert len(result) == 0

    def test_logstore_retention_period_pass(self):
        sls_client = mock.MagicMock
        project_name = "test-project"
        logstore_name = "test-logstore"
        logstore_arn = f"acs:sls:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:logstore/{project_name}/{logstore_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import Logstore

            sls_client.logstores = {
                logstore_arn: Logstore(
                    logstore_name=logstore_name,
                    project_name=project_name,
                    arn=logstore_arn,
                    region=ALIBABACLOUD_REGION,
                    ttl=365,
                    shard_count=2,
                )
            }
            sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = sls_logstore_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == logstore_name
            assert result[0].resource_arn == logstore_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "365 days" in result[0].status_extended
            assert "meets 365+ day requirement" in result[0].status_extended

    def test_logstore_retention_period_fail(self):
        sls_client = mock.MagicMock
        project_name = "test-project"
        logstore_name = "test-logstore"
        logstore_arn = f"acs:sls:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:logstore/{project_name}/{logstore_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import Logstore

            sls_client.logstores = {
                logstore_arn: Logstore(
                    logstore_name=logstore_name,
                    project_name=project_name,
                    arn=logstore_arn,
                    region=ALIBABACLOUD_REGION,
                    ttl=30,
                    shard_count=2,
                )
            }
            sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = sls_logstore_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == logstore_name
            assert result[0].resource_arn == logstore_arn
            assert result[0].region == ALIBABACLOUD_REGION
            assert "only 30 days" in result[0].status_extended
            assert "Increase to at least 365 days" in result[0].status_extended

    def test_logstore_retention_period_greater_than_365(self):
        sls_client = mock.MagicMock
        project_name = "test-project"
        logstore_name = "test-logstore"
        logstore_arn = f"acs:sls:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:logstore/{project_name}/{logstore_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_logstore_retention_period.sls_logstore_retention_period import (
                sls_logstore_retention_period,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import Logstore

            sls_client.logstores = {
                logstore_arn: Logstore(
                    logstore_name=logstore_name,
                    project_name=project_name,
                    arn=logstore_arn,
                    region=ALIBABACLOUD_REGION,
                    ttl=730,  # 2 years
                    shard_count=2,
                )
            }
            sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = sls_logstore_retention_period()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == logstore_name
            assert "730 days" in result[0].status_extended
