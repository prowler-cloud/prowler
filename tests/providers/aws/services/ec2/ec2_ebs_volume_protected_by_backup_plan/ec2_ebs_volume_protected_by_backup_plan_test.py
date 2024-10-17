from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_ebs_volume_protected_by_backup_plan:
    @mock_aws
    def test_ec2_no_volumes(self):
        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=EC2(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_ec2_ebs_volume_no_backup_plans(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2_client.create_volume(
            AvailabilityZone="us-east-1a", Size=10, VolumeType="gp2"
        )

        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=EC2(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"EBS Volume {volume['VolumeId']} is not protected by a backup plan."
                )
                assert result[0].resource_id == volume["VolumeId"]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume['VolumeId']}"
                )
                assert result[0].resource_tags is None

    @mock_aws
    def test_ec2_ebs_volume_without_backup_plan(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        backup_client = client("backup", region_name=AWS_REGION_US_EAST_1)
        volume = ec2_client.create_volume(
            AvailabilityZone="us-east-1a", Size=10, VolumeType="gp2"
        )
        backup_client.create_backup_plan(
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
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=EC2(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=Backup(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"EBS Volume {volume['VolumeId']} is not protected by a backup plan."
                )
                assert result[0].resource_id == volume["VolumeId"]
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume['VolumeId']}"
                )
                assert result[0].resource_tags is None

    def test_ec2_instance_with_backup_plan(self):
        ec2_client = mock.MagicMock()
        from prowler.providers.aws.services.ec2.ec2_service import Volume

        ec2_client.volumes = [
            Volume(
                id="volume-tester",
                arn=f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester",
                tags=None,
                region=AWS_REGION_US_EAST_1,
                encrypted=False,
            )
        ]

        backup_client = mock.MagicMock()
        backup_client.protected_resources = [
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester"
        ]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_client.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=backup_client,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup_client,
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "EBS Volume volume-tester is protected by a backup plan."
                )
                assert result[0].resource_id == "volume-tester"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester"
                )
                assert result[0].resource_tags is None

    def test_ec2_instance_with_backup_plan_via_volume_wildcard(self):
        ec2_client = mock.MagicMock()
        from prowler.providers.aws.services.ec2.ec2_service import Volume

        ec2_client.audited_partition = "aws"
        ec2_client.volumes = [
            Volume(
                id="volume-tester",
                arn=f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester",
                tags=None,
                region=AWS_REGION_US_EAST_1,
                encrypted=False,
            )
        ]

        backup_client = mock.MagicMock()
        backup_client.protected_resources = ["arn:aws:ec2:*:*:volume/*"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_client.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=backup_client,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup_client,
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "EBS Volume volume-tester is protected by a backup plan."
                )
                assert result[0].resource_id == "volume-tester"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester"
                )
                assert result[0].resource_tags is None

    def test_ec2_instance_with_backup_plan_via_all_wildcard(self):
        ec2_client = mock.MagicMock()
        from prowler.providers.aws.services.ec2.ec2_service import Volume

        ec2_client.volumes = [
            Volume(
                id="volume-tester",
                arn=f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester",
                tags=None,
                region=AWS_REGION_US_EAST_1,
                encrypted=False,
            )
        ]

        backup_client = mock.MagicMock()
        backup_client.protected_resources = ["*"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_client.ec2_client",
                new=ec2_client,
            ), mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan.backup_client",
                new=backup_client,
            ), mock.patch(
                "prowler.providers.aws.services.backup.backup_client.backup_client",
                new=backup_client,
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                check = ec2_ebs_volume_protected_by_backup_plan()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "EBS Volume volume-tester is protected by a backup plan."
                )
                assert result[0].resource_id == "volume-tester"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/volume-tester"
                )
                assert result[0].resource_tags is None
