from datetime import datetime
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_encrypted(self, operation_name, kwarg):
    if operation_name == "ListRecoveryPointsByBackupVault":
        return {
            "RecoveryPoints": [
                {
                    "RecoveryPointArn": "arn:aws:backup:eu-west-1:123456789012:recovery-point:1",
                    "BackupVaultName": "Test Vault",
                    "BackupVaultArn": "arn:aws:backup:eu-west-1:123456789012:backup-vault:Test Vault",
                    "BackupVaultRegion": "eu-west-1",
                    "CreationDate": datetime(2015, 1, 1),
                    "Status": "COMPLETED",
                    "EncryptionKeyArn": "",
                    "ResourceArn": "arn:aws:dynamodb:eu-west-1:123456789012:table/MyDynamoDBTable",
                    "ResourceType": "DynamoDB",
                    "BackupPlanId": "ID-TestBackupPlan",
                    "VersionId": "test_version_id",
                    "IsEncrypted": True,
                }
            ]
        }
    if operation_name == "ListBackupVaults":
        return {
            "BackupVaultList": [
                {
                    "BackupVaultArn": "ARN",
                    "BackupVaultName": "Test Vault",
                    "EncryptionKeyArn": "",
                    "NumberOfRecoveryPoints": 0,
                    "Locked": True,
                    "MinRetentionDays": 1,
                    "MaxRetentionDays": 2,
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_not_encrypted(self, operation_name, kwarg):
    if operation_name == "ListRecoveryPointsByBackupVault":
        return {
            "RecoveryPoints": [
                {
                    "RecoveryPointArn": "arn:aws:backup:eu-west-1:123456789012:recovery-point:1",
                    "BackupVaultName": "Test Vault",
                    "BackupVaultArn": "arn:aws:backup:eu-west-1:123456789012:backup-vault:Test Vault",
                    "BackupVaultRegion": "eu-west-1",
                    "CreationDate": datetime(2015, 1, 1),
                    "Status": "COMPLETED",
                    "EncryptionKeyArn": "",
                    "ResourceArn": "arn:aws:dynamodb:eu-west-1:123456789012:table/MyDynamoDBTable",
                    "ResourceType": "DynamoDB",
                    "BackupPlanId": "ID-TestBackupPlan",
                    "VersionId": "test_version_id",
                    "IsEncrypted": False,
                }
            ]
        }
    if operation_name == "ListBackupVaults":
        return {
            "BackupVaultList": [
                {
                    "BackupVaultArn": "ARN",
                    "BackupVaultName": "Test Vault",
                    "EncryptionKeyArn": "",
                    "NumberOfRecoveryPoints": 0,
                    "Locked": True,
                    "MinRetentionDays": 1,
                    "MaxRetentionDays": 2,
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_backup_recovery_point_encrypted:
    @mock_aws
    def test_no_backup_recovery_points(self):
        backup_client = client("backup", region_name=AWS_REGION_EU_WEST_1)
        backup_client.recovery_points = []

        from prowler.providers.aws.services.backup.backup_service import Backup

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted.backup_client",
                new=Backup(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted import (
                backup_recovery_point_encrypted,
            )

            check = backup_recovery_point_encrypted()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_backup_recovery_points_not_encrypted(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_not_encrypted,
        ):
            # backup_client = client("backup", region_name=AWS_REGION_EU_WEST_1)
            # backup_client.recovery_points = []

            from prowler.providers.aws.services.backup.backup_service import Backup

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted.backup_client",
                    new=Backup(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted import (
                    backup_recovery_point_encrypted,
                )

                check = backup_recovery_point_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].status_extended == (
                    "Backup Recovery Point 1 for Backup Vault Test Vault is not encrypted at rest."
                )
                assert result[0].resource_id == "1"
                assert (
                    result[0].resource_arn
                    == "arn:aws:backup:eu-west-1:123456789012:recovery-point:1"
                )
                assert result[0].resource_tags == []
                assert result[0].region == "eu-west-1"

    @mock_aws
    def test_backup_recovery_points_encrypted(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_encrypted,
        ):
            # backup_client = client("backup", region_name=AWS_REGION_EU_WEST_1)
            # backup_client.recovery_points = []

            from prowler.providers.aws.services.backup.backup_service import Backup

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted.backup_client",
                    new=Backup(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.backup.backup_recovery_point_encrypted.backup_recovery_point_encrypted import (
                    backup_recovery_point_encrypted,
                )

                check = backup_recovery_point_encrypted()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].status_extended == (
                    "Backup Recovery Point 1 for Backup Vault Test Vault is encrypted at rest."
                )
                assert result[0].resource_id == "1"
                assert (
                    result[0].resource_arn
                    == "arn:aws:backup:eu-west-1:123456789012:recovery-point:1"
                )
                assert result[0].resource_tags == []
                assert result[0].region == "eu-west-1"
