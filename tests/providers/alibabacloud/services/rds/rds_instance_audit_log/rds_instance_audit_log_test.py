from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_rds_instance_audit_log:
    def test_no_db_instances(self):
        rds_client = mock.MagicMock
        rds_client.db_instances = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log import (
                rds_instance_audit_log,
            )

            check = rds_instance_audit_log()
            result = check.execute()
            assert len(result) == 0

    def test_db_instance_audit_log_enabled_pass(self):
        rds_client = mock.MagicMock
        db_instance_id = "rm-test123"
        db_instance_arn = (
            f"acs:rds:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:dbinstance/{db_instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log import (
                rds_instance_audit_log,
            )
            from prowler.providers.alibabacloud.services.rds.rds_service import (
                DBInstance,
            )

            rds_client.db_instances = {
                db_instance_arn: DBInstance(
                    db_instance_id=db_instance_id,
                    db_instance_name="test-db",
                    arn=db_instance_arn,
                    region=ALIBABACLOUD_REGION,
                    audit_log_enabled=True,
                )
            }
            rds_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = rds_instance_audit_log()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == db_instance_id
            assert "has SQL audit logging enabled" in result[0].status_extended

    def test_db_instance_audit_log_enabled_fail(self):
        rds_client = mock.MagicMock
        db_instance_id = "rm-test456"
        db_instance_arn = (
            f"acs:rds:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:dbinstance/{db_instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_audit_log.rds_instance_audit_log import (
                rds_instance_audit_log,
            )
            from prowler.providers.alibabacloud.services.rds.rds_service import (
                DBInstance,
            )

            rds_client.db_instances = {
                db_instance_arn: DBInstance(
                    db_instance_id=db_instance_id,
                    db_instance_name="test-db",
                    arn=db_instance_arn,
                    region=ALIBABACLOUD_REGION,
                    audit_log_enabled=False,
                )
            }
            rds_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = rds_instance_audit_log()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == db_instance_id
            assert "does not have SQL audit logging enabled" in result[0].status_extended
