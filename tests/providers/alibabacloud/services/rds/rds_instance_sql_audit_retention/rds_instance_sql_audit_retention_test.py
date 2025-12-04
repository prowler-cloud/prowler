from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    set_mocked_alibabacloud_provider,
)


class TestRdsInstanceSqlAuditRetention:
    def test_enabled_short_retention_fails(self):
        rds_client = mock.MagicMock()
        rds_client.audited_account = "1234567890"
        rds_client.audit_config = {"min_rds_audit_retention_days": 180}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.rds.rds_instance_sql_audit_retention.rds_instance_sql_audit_retention.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_sql_audit_retention.rds_instance_sql_audit_retention import (
                rds_instance_sql_audit_retention,
            )
            from prowler.providers.alibabacloud.services.rds.rds_service import (
                DBInstance,
            )

            instance = DBInstance(
                id="db-1",
                name="db-1",
                region="cn-hangzhou",
                engine="MySQL",
                engine_version="8.0",
                status="Running",
                type="Primary",
                net_type="VPC",
                connection_mode="Standard",
                public_connection_string="",
                ssl_enabled=True,
                tde_status="Enabled",
                tde_key_id="",
                security_ips=[],
                audit_log_enabled=True,
                audit_log_retention=30,
                log_connections="",
                log_disconnections="",
                log_duration="",
            )
            rds_client.instances = [instance]

            check = rds_instance_sql_audit_retention()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"

    def test_enabled_long_retention_passes(self):
        rds_client = mock.MagicMock()
        rds_client.audited_account = "1234567890"
        rds_client.audit_config = {"min_rds_audit_retention_days": 180}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_alibabacloud_provider(),
            ),
            mock.patch(
                "prowler.providers.alibabacloud.services.rds.rds_instance_sql_audit_retention.rds_instance_sql_audit_retention.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_sql_audit_retention.rds_instance_sql_audit_retention import (
                rds_instance_sql_audit_retention,
            )
            from prowler.providers.alibabacloud.services.rds.rds_service import (
                DBInstance,
            )

            instance = DBInstance(
                id="db-2",
                name="db-2",
                region="cn-hangzhou",
                engine="MySQL",
                engine_version="8.0",
                status="Running",
                type="Primary",
                net_type="VPC",
                connection_mode="Standard",
                public_connection_string="",
                ssl_enabled=True,
                tde_status="Enabled",
                tde_key_id="",
                security_ips=[],
                audit_log_enabled=True,
                audit_log_retention=365,
                log_connections="",
                log_disconnections="",
                log_duration="",
            )
            rds_client.instances = [instance]

            check = rds_instance_sql_audit_retention()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
