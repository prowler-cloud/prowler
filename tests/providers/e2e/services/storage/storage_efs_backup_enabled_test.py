from unittest import mock

from prowler.providers.e2e.services.storage.storage_service import EfsVolume
from tests.providers.e2e.e2e_fixtures import set_mocked_e2e_provider


class TestStorageEfsBackupEnabledCheck:
    def test_pass_and_fail(self):
        storage_client = mock.MagicMock()
        storage_client.efs_volumes = [
            EfsVolume(
                id="1",
                name="efs-ok",
                location="Delhi",
                is_backup_enabled=True,
            ),
            EfsVolume(
                id="2",
                name="efs-bad",
                location="Delhi",
                is_backup_enabled=False,
            ),
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_e2e_provider(),
            ),
            mock.patch(
                "prowler.providers.e2e.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled.storage_client",
                new=storage_client,
            ),
        ):
            from prowler.providers.e2e.services.storage.storage_efs_backup_enabled.storage_efs_backup_enabled import (
                storage_efs_backup_enabled,
            )

            findings = storage_efs_backup_enabled().execute()

            assert len(findings) == 2
            assert findings[0].status == "PASS"
            assert findings[1].status == "FAIL"
