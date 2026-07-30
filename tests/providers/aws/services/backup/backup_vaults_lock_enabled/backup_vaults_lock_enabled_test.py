from unittest import mock

from prowler.providers.aws.services.backup.backup_service import BackupVault
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

VAULT_NAME = "MyBackupVault"
VAULT_ARN = f"arn:aws:backup:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:backup-vault:{VAULT_NAME}"

CHECK_PATH = "prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled.backup_client"


def build_vault(locked: bool) -> BackupVault:
    return BackupVault(
        arn=VAULT_ARN,
        name=VAULT_NAME,
        region=AWS_REGION_EU_WEST_1,
        encryption="test",
        recovery_points=1,
        locked=locked,
        min_retention_days=7,
        max_retention_days=365,
        tags=[],
    )


class Test_backup_vaults_lock_enabled:
    def test_no_backup_vaults(self):
        backup_client = mock.MagicMock()
        backup_client.backup_vaults = []

        with (
            mock.patch(
                "prowler.providers.aws.services.backup.backup_service.Backup",
                new=backup_client,
            ),
            mock.patch(CHECK_PATH, new=backup_client),
        ):
            from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                backup_vaults_lock_enabled,
            )

            check = backup_vaults_lock_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_backup_vaults_none(self):
        backup_client = mock.MagicMock()
        backup_client.backup_vaults = None

        with (
            mock.patch(
                "prowler.providers.aws.services.backup.backup_service.Backup",
                new=backup_client,
            ),
            mock.patch(CHECK_PATH, new=backup_client),
        ):
            from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                backup_vaults_lock_enabled,
            )

            check = backup_vaults_lock_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_backup_vault_not_locked(self):
        backup_client = mock.MagicMock()
        backup_client.backup_vaults = [build_vault(locked=False)]

        with (
            mock.patch(
                "prowler.providers.aws.services.backup.backup_service.Backup",
                new=backup_client,
            ),
            mock.patch(CHECK_PATH, new=backup_client),
        ):
            from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                backup_vaults_lock_enabled,
            )

            check = backup_vaults_lock_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Backup Vault {VAULT_NAME} does not have Vault Lock enabled."
            )
            assert result[0].resource_id == VAULT_NAME
            assert result[0].resource_arn == VAULT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_backup_vault_locked(self):
        backup_client = mock.MagicMock()
        backup_client.backup_vaults = [build_vault(locked=True)]

        with (
            mock.patch(
                "prowler.providers.aws.services.backup.backup_service.Backup",
                new=backup_client,
            ),
            mock.patch(CHECK_PATH, new=backup_client),
        ):
            from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                backup_vaults_lock_enabled,
            )

            check = backup_vaults_lock_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Backup Vault {VAULT_NAME} has Vault Lock enabled."
            )
            assert result[0].resource_id == VAULT_NAME
            assert result[0].resource_arn == VAULT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
