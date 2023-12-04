from unittest import mock

from prowler.providers.aws.services.backup.backup_service import BackupVault
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)


class Test_backup_vaults_exist:
    def test_no_backup_vaults(self):
        backup_client = mock.MagicMock
        backup_client.audited_account = AWS_ACCOUNT_NUMBER
        backup_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        backup_client.region = AWS_REGION_EU_WEST_1
        backup_client.backup_vaults = []
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_vaults_exist.backup_vaults_exist import (
                backup_vaults_exist,
            )

            check = backup_vaults_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "No Backup Vault exist."
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_one_backup_vault(self):
        backup_client = mock.MagicMock
        backup_client.audited_account = AWS_ACCOUNT_NUMBER
        backup_client.audited_account_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
        backup_client.region = AWS_REGION_EU_WEST_1
        backup_vault_arn = f"arn:aws:backup:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:backup-vault:MyBackupVault"
        backup_client.backup_vaults = [
            BackupVault(
                arn=backup_vault_arn,
                name="MyBackupVault",
                region=AWS_REGION_EU_WEST_1,
                encryption="",
                recovery_points=1,
                locked=True,
                min_retention_days=1,
                max_retention_days=2,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_vaults_exist.backup_vaults_exist import (
                backup_vaults_exist,
            )

            check = backup_vaults_exist()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"At least one backup vault exists: {result[0].resource_id}."
            )
            assert result[0].resource_id == "MyBackupVault"
            assert result[0].resource_arn == backup_vault_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
