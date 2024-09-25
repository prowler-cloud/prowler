from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


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

    def test_rds_instance_without_backup_plan(self):
        instance = mock.MagicMock
        backup = mock.MagicMock

        from prowler.providers.aws.services.rds.rds_service import DBInstance

        arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
        instance.db_instances = {
            arn: DBInstance(
                "db-master-1",
                "us-east-1",
                "db.m1.small",
                "postgres",
                "staging-postgres",
                10,
                [],
            )
        }

        backup.protected_resources = [
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-2"
        ]

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.provider.aws.services.rds.rds_service.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
            new=backup,
        ), mock.patch(
            "prowler.providers.aws.services.backup.backup_service.backup_client",
            new=backup,
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

    def test_rds_instance_with_backup_plan(self):
        instance = mock.MagicMock
        backup = mock.MagicMock

        from prowler.providers.aws.services.rds.rds_service import DBInstance

        arn = f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
        instance.db_instances = {
            arn: DBInstance(
                "db-master-1",
                "us-east-1",
                "db.m1.small",
                "postgres",
                "staging-postgres",
                10,
                [],
            )
        }

        backup.protected_resources = [arn]

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.provider.aws.services.rds.rds_service.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
            new=backup,
        ), mock.patch(
            "prowler.providers.aws.services.backup.backup_service.backup_client",
            new=backup,
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

    def test_rds_instance_with_backup_plan_via_instance_wildcard(self):
        instance = mock.MagicMock
        backup = mock.MagicMock

        from prowler.providers.aws.services.rds.rds_service import DBInstance

        arn = "arn:aws:dynamodb:*:*:instance:*"
        instance.db_instances = {
            arn: DBInstance(
                "db-master-1",
                "us-east-1",
                "db.m1.small",
                "postgres",
                "staging-postgres",
                10,
                [],
            )
        }

        backup.protected_resources = [arn]

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.provider.aws.services.rds.rds_service.rds_client",
            new=instance,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_protected_by_backup_plan.rds_instance_protected_by_backup_plan.backup_client",
            new=backup,
        ), mock.patch(
            "prowler.providers.aws.services.backup.backup_service.backup_client",
            new=backup,
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
