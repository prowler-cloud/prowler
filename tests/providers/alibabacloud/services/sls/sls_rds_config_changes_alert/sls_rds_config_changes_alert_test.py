from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_sls_alert_rds_config_changes:
    def test_no_alerts(self):
        sls_client = mock.MagicMock
        sls_client.alerts = {}
        sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes import (
                sls_alert_rds_config_changes,
            )

            check = sls_alert_rds_config_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sls-alerts"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "No enabled alerts found" in result[0].status_extended

    def test_alert_enabled_pass(self):
        sls_client = mock.MagicMock
        sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        project_name = "test-project"
        alert_name = "test-rds-config-alert"
        alert_arn = f"acs:sls:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:alert/{project_name}/{alert_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes import (
                sls_alert_rds_config_changes,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import Alert

            sls_client.alerts = {
                alert_arn: Alert(
                    name=alert_name,
                    display_name="Alert for RDS Configuration Changes",
                    project_name=project_name,
                    arn=alert_arn,
                    region=ALIBABACLOUD_REGION,
                    state="Enabled",
                )
            }

            check = sls_alert_rds_config_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == "sls-alerts"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "1 enabled alert" in result[0].status_extended
            assert "RDS Configuration Changes" in result[0].status_extended

    def test_alert_disabled_fail(self):
        sls_client = mock.MagicMock
        sls_client.account_id = ALIBABACLOUD_ACCOUNT_ID

        project_name = "test-project"
        alert_name = "test-rds-config-alert"
        alert_arn = f"acs:sls:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:alert/{project_name}/{alert_name}"

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes.sls_client",
            new=sls_client,
        ):
            from prowler.providers.alibabacloud.services.sls.sls_alert_rds_config_changes.sls_alert_rds_config_changes import (
                sls_alert_rds_config_changes,
            )
            from prowler.providers.alibabacloud.services.sls.sls_service import Alert

            sls_client.alerts = {
                alert_arn: Alert(
                    name=alert_name,
                    display_name="Alert for RDS Configuration Changes",
                    project_name=project_name,
                    arn=alert_arn,
                    region=ALIBABACLOUD_REGION,
                    state="Disabled",
                )
            }

            check = sls_alert_rds_config_changes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == "sls-alerts"
            assert result[0].account_uid == ALIBABACLOUD_ACCOUNT_ID
            assert result[0].region == "global"
            assert "No enabled alerts found" in result[0].status_extended
