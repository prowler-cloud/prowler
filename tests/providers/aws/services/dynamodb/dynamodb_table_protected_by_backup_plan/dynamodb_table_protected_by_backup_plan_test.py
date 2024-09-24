from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "CreateBackupSelection":
        return {
            "SelectionName": "test-backup-selection",
            "IamRoleArn": "arn:aws:iam::123456789012:role/backup-role",
            "Resources": [
                f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/test1",
            ],
        }
    elif operation_name == "ListProtectedResources":
        return {
            "Results": [
                {
                    "ResourceArn": f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/test1",
                    "ResourceType": "DynamoDB",
                    "LastBackupTime": "2023-08-23T00:00:00Z",
                }
            ]
        }
    elif operation_name == "ListBackupPlans":
        return {
            "BackupPlans": [
                {
                    "BackupPlanId": "test-backup-plan-id",
                    "BackupPlanName": "test-backup-plan",
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_dynamodb_table_protected_by_backup_plan:
    @mock_aws
    def test_dynamodb_no_tables(self):
        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.dynamodb_client",
                new=DynamoDB(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan import (
                    dynamodb_table_protected_by_backup_plan,
                )

                check = dynamodb_table_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_dynamodb_table_no_existing_backup_plans(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table = dynamodb_client.create_table(
            TableName="test1",
            AttributeDefinitions=[
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "app", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "client", "KeyType": "HASH"},
                {"AttributeName": "app", "KeyType": "RANGE"},
            ],
            DeletionProtectionEnabled=True,
            BillingMode="PAY_PER_REQUEST",
        )["TableDescription"]

        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.dynamodb_client",
                new=DynamoDB(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan import (
                    dynamodb_table_protected_by_backup_plan,
                )

                check = dynamodb_table_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "DynamoDB table test1 is not protected by a backup plan."
                )
                assert result[0].resource_id == table["TableName"]
                assert result[0].resource_arn == table["TableArn"]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_without_backup_plan(self):
        backup = client("backup", region_name=AWS_REGION_US_EAST_1)
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table = dynamodb_client.create_table(
            TableName="test1",
            AttributeDefinitions=[
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "app", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "client", "KeyType": "HASH"},
                {"AttributeName": "app", "KeyType": "RANGE"},
            ],
            DeletionProtectionEnabled=True,
            BillingMode="PAY_PER_REQUEST",
        )["TableDescription"]

        backup.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "test-backup-plan",
                "Rules": [
                    {
                        "RuleName": "DailyBackup",
                        "TargetBackupVaultName": "test-vault",
                        "ScheduleExpression": "cron(0 12 * * ? *)",
                        "Lifecycle": {"DeleteAfterDays": 30},
                        "RecoveryPointTags": {
                            "Type": "Daily",
                        },
                    },
                ],
            }
        )

        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.dynamodb_client",
                new=DynamoDB(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan import (
                    dynamodb_table_protected_by_backup_plan,
                )

                check = dynamodb_table_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "DynamoDB table test1 is not protected by a backup plan."
                )
                assert result[0].resource_id == table["TableName"]
                assert result[0].resource_arn == table["TableArn"]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_with_backup_plan(self):
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            backup = client("backup", region_name=AWS_REGION_US_EAST_1)
            dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
            table = dynamodb_client.create_table(
                TableName="test1",
                AttributeDefinitions=[
                    {"AttributeName": "client", "AttributeType": "S"},
                    {"AttributeName": "app", "AttributeType": "S"},
                ],
                KeySchema=[
                    {"AttributeName": "client", "KeyType": "HASH"},
                    {"AttributeName": "app", "KeyType": "RANGE"},
                ],
                DeletionProtectionEnabled=True,
                BillingMode="PAY_PER_REQUEST",
            )["TableDescription"]
            backup.create_backup_plan(
                BackupPlan={
                    "BackupPlanName": "test-backup-plan",
                    "Rules": [
                        {
                            "RuleName": "DailyBackup",
                            "TargetBackupVaultName": "test-vault",
                            "ScheduleExpression": "cron(0 12 * * ? *)",
                            "Lifecycle": {"DeleteAfterDays": 30},
                            "RecoveryPointTags": {
                                "Type": "Daily",
                            },
                        },
                    ],
                }
            )
            backup.create_backup_selection(
                BackupPlanID={
                    backup.list_backup_plans()["BackupPlans"][0]["BackupPlanId"]
                },
                BackupPlanSelection={
                    "SelectionName": "test-backup-selection",
                    "IamRoleArn": "arn:aws:iam::123456789012:role/backup-role",
                    "Resources": [
                        f"{table['TableArn']}",
                    ],
                },
            )

            from prowler.providers.aws.services.backup.backup_service import Backup
            from prowler.providers.aws.services.dynamodb.dynamodb_service import (
                DynamoDB,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.dynamodb_client",
                    new=DynamoDB(aws_provider),
                ), mock.patch(
                    "prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan.backup_client",
                    new=Backup(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.dynamodb.dynamodb_table_protected_by_backup_plan.dynamodb_table_protected_by_backup_plan import (
                        dynamodb_table_protected_by_backup_plan,
                    )

                    check = dynamodb_table_protected_by_backup_plan()
                    result = check.execute()

                    assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "DynamoDB table test1 is protected by a backup plan."
                )
                assert result[0].resource_id == table["TableName"]
                assert result[0].resource_arn == table["TableArn"]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].resource_tags == []
