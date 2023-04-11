from unittest import mock

from prowler.providers.aws.services.backup.backup_service import BackupVault

AWS_REGION = "eu-west-1"


class Test_backup_vaults_encrypted:
    def test_no_backup_vaults(self):
        backup_client = mock.MagicMock
        backup_client.backup_vaults = []
        with mock.patch(
            "prowler.providers.aws.services.backup.backup_service.Backup",
            new=backup_client,
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_vaults_encrypted.backup_vaults_encrypted import (
                backup_vaults_encrypted,
            )

            check = backup_vaults_encrypted()
            result = check.execute()

            assert len(result) == 0

    def test_one_backup_vault_unencrypted(self):
        backup_client = mock.MagicMock
        backup_client.backup_vaults = [
            BackupVault(
                arn="ARN",
                name="MyBackupVault",
                region=AWS_REGION,
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
            from prowler.providers.aws.services.backup.backup_vaults_encrypted.backup_vaults_encrypted import (
                backup_vaults_encrypted,
            )

            check = backup_vaults_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Backup Vault " + result[0].resource_id + " is not encrypted"
            )
            assert result[0].resource_id == "MyBackupVault"
            assert result[0].resource_arn == "ARN"
            assert result[0].region == AWS_REGION

    def test_one_backup_vault_encrypted(self):
        backup_client = mock.MagicMock
        backup_client.backup_vaults = [
            BackupVault(
                arn="ARN",
                name="MyBackupVault",
                region=AWS_REGION,
                encryption="test",
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
            from prowler.providers.aws.services.backup.backup_vaults_encrypted.backup_vaults_encrypted import (
                backup_vaults_encrypted,
            )

            check = backup_vaults_encrypted()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Backup Vault " + result[0].resource_id + " is encrypted"
            )
            assert result[0].resource_id == "MyBackupVault"
            assert result[0].resource_arn == "ARN"
            assert result[0].region == AWS_REGION
