from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_rds_instance_non_default_port:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_default_port(self):
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
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using the default port 5432 for postgres."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_instance_non_default_port_sg_not_allowed(self):
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
            Port=5433,
            Tags=[{"Key": "test", "Value": "test"}],
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using a non-default port (5433) for postgres, but none of the associated security groups allow access to this port."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]

    @mock_aws
    def test_rds_instance_non_default_port_sg_allowed(self):
        ec2_conn = client("ec2", region_name=AWS_REGION_US_EAST_1)
        sg = ec2_conn.create_security_group(
            GroupName="my-security-group",
            Description="Test Security Group",
            VpcId="vpc-12345678",
        )

        ec2_conn.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5433,
                    "ToPort": 5433,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

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
            Port=5433,
            VpcSecurityGroupIds=[sg["GroupId"]],
            Tags=[{"Key": "test", "Value": "test"}],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port.ec2_client",
                new=EC2(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_non_default_port.rds_instance_non_default_port import (
                    rds_instance_non_default_port,
                )

                check = rds_instance_non_default_port()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is using a non-default port (5433) for postgres and the security group vpc-12345678 allows access on this port."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == [{"Key": "test", "Value": "test"}]
