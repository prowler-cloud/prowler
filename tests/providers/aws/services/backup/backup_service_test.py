from datetime import datetime
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.backup.backup_service import Backup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

# Mocking Backup Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    """
    Mock every AWS API call
    """
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
    if operation_name == "ListBackupPlans":
        return {
            "BackupPlansList": [
                {
                    "BackupPlanArn": "ARN",
                    "BackupPlanId": "ID",
                    "BackupPlanName": "Test Plan",
                    "VersionId": "test_version_id",
                    "LastExecutionDate": datetime(2015, 1, 1),
                    "AdvancedBackupSettings": [],
                }
            ]
        }
    if operation_name == "ListReportPlans":
        return {
            "ReportPlans": [
                {
                    "ReportPlanArn": "ARN",
                    "ReportPlanName": "Test Report Plan",
                    "LastAttemptedExecutionTime": datetime(2015, 1, 1),
                    "LastSuccessfulExecutionTime": datetime(2015, 1, 1),
                }
            ]
        }
    if operation_name == "ListBackupSelections":
        return {
            "BackupSelectionsList": [
                {
                    "SelectionId": "selection-id-1",
                    "SelectionName": "TestSelection",
                    "BackupPlanId": "ID-TestBackupPlan",
                    "CreationDate": datetime(2015, 1, 1),
                    "CreatorRequestId": "request-id-1",
                    "IamRoleArn": "arn:aws:iam::123456789012:role/service-role/AWSBackupDefaultServiceRole",
                }
            ]
        }
    if operation_name == "GetBackupSelection":
        return {
            "BackupSelection": {
                "SelectionName": "TestSelection",
                "IamRoleArn": "arn:aws:iam::123456789012:role/service-role/AWSBackupDefaultServiceRole",
                "Resources": [
                    "arn:aws:dynamodb:eu-west-1:123456789012:table/MyDynamoDBTable"
                ],
            },
            "SelectionId": "selection-id-1",
            "BackupPlanId": "ID-TestBackupPlan",
            "CreationDate": datetime(2015, 1, 1),
            "CreatorRequestId": "request-id-1",
        }
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
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


class TestBackupService:
    # Test Backup Client
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_get_client(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert (
            backup.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__ == "Backup"
        )

    # Test Backup Session
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        access_analyzer = Backup(aws_provider)
        assert access_analyzer.session.__class__.__name__ == "Session"

    # Test Backup Serviceç
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test__get_service__(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        access_analyzer = Backup(aws_provider)
        assert access_analyzer.service == "backup"

    # Test Backup List Backup Vaults
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_list_backup_vaults(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert len(backup.backup_vaults) == 1
        assert backup.backup_vaults[0].arn == "ARN"
        assert backup.backup_vaults[0].name == "Test Vault"
        assert backup.backup_vaults[0].region == AWS_REGION_EU_WEST_1
        assert backup.backup_vaults[0].encryption == ""
        assert backup.backup_vaults[0].recovery_points == 0
        assert backup.backup_vaults[0].locked is True
        assert backup.backup_vaults[0].min_retention_days == 1
        assert backup.backup_vaults[0].max_retention_days == 2

    # Test Backup List Backup Plans
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_list_backup_plans(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert len(backup.backup_plans) == 1
        assert backup.backup_plans[0].arn == "ARN"
        assert backup.backup_plans[0].id == "ID"
        assert backup.backup_plans[0].region == AWS_REGION_EU_WEST_1
        assert backup.backup_plans[0].name == "Test Plan"
        assert backup.backup_plans[0].version_id == "test_version_id"
        assert backup.backup_plans[0].last_execution_date == datetime(2015, 1, 1)
        assert backup.backup_plans[0].advanced_settings == []

    # Test Backup List Report Plans
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_list_backup_report_plans(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert len(backup.backup_report_plans) == 1
        assert backup.backup_report_plans[0].arn == "ARN"
        assert backup.backup_report_plans[0].region == AWS_REGION_EU_WEST_1
        assert backup.backup_report_plans[0].name == "Test Report Plan"
        assert backup.backup_report_plans[0].last_attempted_execution_date == datetime(
            2015, 1, 1
        )
        assert backup.backup_report_plans[0].last_successful_execution_date == datetime(
            2015, 1, 1
        )

    # Test Backup List Backup Selections
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_list_backup_selections(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert len(backup.protected_resources) == 1
        assert (
            "arn:aws:dynamodb:eu-west-1:123456789012:table/MyDynamoDBTable"
            in backup.protected_resources
        )

    @mock_aws
    def test_list_tags(self):
        backup_client = client("backup", region_name=AWS_REGION_EU_WEST_1)

        # Create necessary resources and tags
        backup_vault = backup_client.create_backup_vault(
            BackupVaultName="TestVault",
            EncryptionKeyArn=f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-123456789012",
        )

        tags = {"TestKey": "TestValue"}

        backup_client.tag_resource(
            ResourceArn=backup_vault["BackupVaultArn"], Tags=tags
        )

        # Create a backup plan
        backup_plan = backup_client.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "TestPlan",
                "Rules": [
                    {
                        "RuleName": "TestRule",
                        "TargetBackupVaultName": "TestVault",  # Match the vault name
                        "ScheduleExpression": "cron(0 12 * * ? *)",
                    }
                ],
            }
        )

        backup_client.tag_resource(ResourceArn=backup_plan["BackupPlanArn"], Tags=tags)

        # Test list_tags
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)

        assert len(backup.backup_vaults) == 1
        assert len(backup.backup_vaults[0].tags) == 1
        assert backup.backup_vaults[0].tags[0]["TestKey"] == "TestValue"
        assert len(backup.backup_plans) == 1
        assert len(backup.backup_plans[0].tags) == 1
        assert backup.backup_plans[0].tags[0]["TestKey"] == "TestValue"

    # Test Backup List Recovery Points
    @mock_aws
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @patch(
        "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
        new=mock_generate_regional_clients,
    )
    def test_list_recovery_points(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        backup = Backup(aws_provider)
        assert len(backup.recovery_points) == 1
        assert (
            backup.recovery_points[0].arn
            == "arn:aws:backup:eu-west-1:123456789012:recovery-point:1"
        )
        assert backup.recovery_points[0].backup_vault_name == "Test Vault"
        assert backup.recovery_points[0].backup_vault_region == "eu-west-1"
        assert backup.recovery_points[0].tags == []
        assert backup.recovery_points[0].encrypted is True
