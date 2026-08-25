from unittest import mock

from tests.providers.huaweicloud.huaweicloud_fixtures import (
    set_mocked_huaweicloud_provider,
)


class TestRdsBackupEnabled:
    def test_backup_enabled_passes(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled import (
                rds_backup_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="backed-up-db",
                backup_enabled=True,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "backup enabled" in result[0].status_extended

    def test_backup_disabled_fails(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled import (
                rds_backup_enabled,
            )
            from prowler.providers.huaweicloud.services.rds.rds_service import (
                RDSInstance,
            )

            instance = RDSInstance(
                id="rds-1",
                name="no-backup-db",
                backup_enabled=False,
                region="la-south-2",
            )
            rds_client.instances = [instance]
            rds_client.audited_account = "123456789012"

            check = rds_backup_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "does not have automated backup" in result[0].status_extended

    def test_no_instances(self):
        rds_client = mock.MagicMock()

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_huaweicloud_provider(),
            ),
            mock.patch(
                "prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled.rds_client",
                new=rds_client,
            ),
        ):
            from prowler.providers.huaweicloud.services.rds.rds_backup_enabled.rds_backup_enabled import (
                rds_backup_enabled,
            )

            rds_client.instances = []
            rds_client.audited_account = "123456789012"

            check = rds_backup_enabled()
            result = check.execute()

            assert len(result) == 0
