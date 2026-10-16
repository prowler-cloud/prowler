from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

VAULT_NAME = "MyBackupVault"
VAULT_ARN = f"arn:aws:backup:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:backup-vault:{VAULT_NAME}"
KMS_KEY_ARN = (
    f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/backup-vault-key"
)

CHECK_PATH = "prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled.backup_client"
PROVIDER_PATH = "prowler.providers.common.provider.Provider.get_global_provider"


make_api_call = botocore.client.BaseClient._make_api_call


def create_vault() -> None:
    client("backup", region_name=AWS_REGION_EU_WEST_1).create_backup_vault(
        BackupVaultName=VAULT_NAME, EncryptionKeyArn=KMS_KEY_ARN
    )


def mock_locked_vault(self, operation_name, kwargs):
    """Report the vault as locked, which moto cannot do on its own.

    The pinned moto answers PutBackupVaultLockConfiguration with "Not yet
    implemented", so Vault Lock cannot be turned on through the API. Only this
    one response is replaced; the vault is still created by moto and the
    service parses this payload exactly as it would parse AWS's.
    """
    if operation_name == "ListBackupVaults":
        return {
            "BackupVaultList": [
                {
                    "BackupVaultName": VAULT_NAME,
                    "BackupVaultArn": VAULT_ARN,
                    "EncryptionKeyArn": KMS_KEY_ARN,
                    "NumberOfRecoveryPoints": 0,
                    "Locked": True,
                    "MinRetentionDays": 7,
                    "MaxRetentionDays": 365,
                }
            ]
        }
    return make_api_call(self, operation_name, kwargs)


class Test_backup_vaults_lock_enabled:
    @mock_aws
    def test_no_backup_vaults(self):
        from prowler.providers.aws.services.backup.backup_service import Backup

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=Backup(aws_provider)):
                from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                    backup_vaults_lock_enabled,
                )

                check = backup_vaults_lock_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_backup_vaults_none(self):
        from prowler.providers.aws.services.backup.backup_service import Backup

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        # The service sets backup_vaults to None when ListBackupVaults is denied,
        # which moto cannot reproduce because it does not enforce IAM. The check
        # must still return no findings instead of raising on the None.
        backup.backup_vaults = None

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=backup):
                from prowler.providers.aws.services.backup.backup_vaults_lock_enabled.backup_vaults_lock_enabled import (
                    backup_vaults_lock_enabled,
                )

                check = backup_vaults_lock_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_backup_vault_not_locked(self):
        from prowler.providers.aws.services.backup.backup_service import Backup

        create_vault()
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=Backup(aws_provider)):
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

    @mock_aws
    def test_backup_vault_locked(self):
        from prowler.providers.aws.services.backup.backup_service import Backup

        create_vault()
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_locked_vault
        ):
            backup = Backup(aws_provider)

        with mock.patch(PROVIDER_PATH, return_value=aws_provider):
            with mock.patch(CHECK_PATH, new=backup):
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
