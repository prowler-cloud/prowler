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
                f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1",
            ],
        }
    elif operation_name == "ListProtectedResources":
        return {
            "Results": [
                {
                    "ResourceArn": f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1",
                    "ResourceType": "RDS",
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


class Test_rds_instance_protected_by_backup_plan:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan import (
                    rds_instance_protected_by_backup_plan,
                )

                check = rds_instance_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_no_existing_backup_plans(self):
        instance = client("rds", region_name=AWS_REGION_US_EAST_1)
        instance.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan import (
                    rds_instance_protected_by_backup_plan,
                )

                check = rds_instance_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is not protected by a backup plan."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_without_backup_plan(self):
        instance = client("rds", region_name=AWS_REGION_US_EAST_1)
        backup = client("backup", region_name=AWS_REGION_US_EAST_1)
        instance.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )
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
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan import (
                    rds_instance_protected_by_backup_plan,
                )

                check = rds_instance_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is not protected by a backup plan."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_with_backup_plan(self):
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            instance = client("rds", region_name=AWS_REGION_US_EAST_1)
            backup = client("backup", region_name=AWS_REGION_US_EAST_1)
            instance.create_db_instance(
                DBInstanceIdentifier="db-master-1",
                AllocatedStorage=10,
                Engine="postgres",
                DBName="staging-postgres",
                DBInstanceClass="db.m1.small",
            )
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
                        f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1",
                    ],
                },
            )

            from prowler.providers.aws.services.backup.backup_service import Backup
            from prowler.providers.aws.services.rds.rds_service import RDS

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
                    new=RDS(aws_provider),
                ), mock.patch(
                    "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
                    new=Backup(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan import (
                        rds_instance_protected_by_backup_plan,
                    )

                    check = rds_instance_protected_by_backup_plan()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == "RDS Instance db-master-1 is protected by a backup plan."
                    )
                    assert result[0].resource_id == "db-master-1"
                    assert result[0].region == AWS_REGION_US_EAST_1
                    assert (
                        result[0].resource_arn
                        == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                    )
                    assert result[0].resource_tags == []
