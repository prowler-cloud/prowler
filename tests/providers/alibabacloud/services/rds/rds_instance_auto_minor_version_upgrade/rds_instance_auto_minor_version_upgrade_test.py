from unittest import mock

from tests.providers.alibabacloud.alibabacloud_fixtures import (
    ALIBABACLOUD_ACCOUNT_ID,
    ALIBABACLOUD_REGION,
    set_mocked_alibabacloud_provider,
)


class Test_rds_instance_auto_minor_version_upgrade:
    def test_no_db_instances(self):
        rds_client = mock.MagicMock
        rds_client.db_instances = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade import (
                rds_instance_auto_minor_version_upgrade,
            )

            check = rds_instance_auto_minor_version_upgrade()
            result = check.execute()
            assert len(result) == 0

    def test_db_instance_auto_minor_version_upgrade_pass(self):
        rds_client = mock.MagicMock
        db_instance_id = "rm-test123"
        db_instance_arn = (
            f"acs:rds:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:dbinstance/{db_instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade import (
                rds_instance_auto_minor_version_upgrade,
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
                    auto_minor_version_upgrade=True,
                )
            }
            rds_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = rds_instance_auto_minor_version_upgrade()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == db_instance_id
            assert "has automatic minor version upgrades enabled" in result[0].status_extended

    def test_db_instance_auto_minor_version_upgrade_fail(self):
        rds_client = mock.MagicMock
        db_instance_id = "rm-test456"
        db_instance_arn = (
            f"acs:rds:{ALIBABACLOUD_REGION}:{ALIBABACLOUD_ACCOUNT_ID}:dbinstance/{db_instance_id}"
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_alibabacloud_provider(),
        ), mock.patch(
            "prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade.rds_client",
            new=rds_client,
        ):
            from prowler.providers.alibabacloud.services.rds.rds_instance_auto_minor_version_upgrade.rds_instance_auto_minor_version_upgrade import (
                rds_instance_auto_minor_version_upgrade,
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
                    auto_minor_version_upgrade=False,
                )
            }
            rds_client.account_id = ALIBABACLOUD_ACCOUNT_ID

            check = rds_instance_auto_minor_version_upgrade()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == db_instance_id
            assert "does not have automatic minor version upgrades enabled" in result[0].status_extended
