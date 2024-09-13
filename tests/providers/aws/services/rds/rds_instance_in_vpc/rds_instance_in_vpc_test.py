from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.rds.rds_service import DBInstance
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_in_vpc:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc import (
                    rds_instance_in_vpc,
                )

                check = rds_instance_in_vpc()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_in_vpc(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            StorageEncrypted=True,
            DeletionProtection=True,
            PubliclyAccessible=True,
            AutoMinorVersionUpgrade=True,
            BackupRetentionPeriod=10,
            Port=5432,
            Tags=[{"Key": "test", "Value": "test"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc import (
                    rds_instance_in_vpc,
                )

                check = rds_instance_in_vpc()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is deployed in a VPC."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    def test_rds_instance_not_in_vpc(self):
        rds_client = mock.MagicMock
        instance_arn = (
            f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
        )
        rds_client.db_instances = {
            instance_arn: DBInstance(
                id="db-master-1",
                arn=instance_arn,
                engine="postgres",
                cloudwatch_logs=None,
                deletion_protection=True,
                auto_minor_version_upgrade=True,
                enhanced_monitoring_arn=None,
                endpoint={
                    "Address": "db-master-1.us-east-1.rds.amazonaws.com",
                    "Port": 5432,
                },
                engine_version="12.3",
                status="available",
                public=False,
                encrypted=False,
                iam_auth=False,
                region=AWS_REGION_US_EAST_1,
                multi_az=False,
                username="admin",
                tags=[{"Key": "test", "Value": "test"}],
                copy_tags_to_snapshot=None,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.rds.rds_service.RDS",
            new=rds_client,
        ), mock.patch(
            "prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc.rds_client",
            new=rds_client,
        ):
            # Test Check
            from prowler.providers.aws.services.rds.rds_instance_in_vpc.rds_instance_in_vpc import (
                rds_instance_in_vpc,
            )

            check = rds_instance_in_vpc()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "RDS Instance db-master-1 is not deployed in a VPC."
            )
            assert result[0].resource_id == "db-master-1"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
            )
            assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]
