from unittest import mock

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
    if operation_name == "DescribeDBEngineVersions":
        return {
            "DBEngineVersions": [
                {
                    "Engine": "mysql",
                    "EngineVersion": "8.0.32",
                    "DBEngineDescription": "description",
                    "DBEngineVersionDescription": "description",
                },
            ]
        }
    return make_api_call(self, operation_name, kwarg)


@mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_rds_instance_no_public_access:
    @mock_aws
    def test_rds_no_instances(self):
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access import (
                    rds_instance_no_public_access,
                )

                check = rds_instance_no_public_access()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_rds_instance_private(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access import (
                    rds_instance_no_public_access,
                )

                check = rds_instance_no_public_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is not publicly accessible."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_public(self):
        conn = client("rds", region_name=AWS_REGION_US_EAST_1)
        conn.create_db_instance(
            DBInstanceIdentifier="db-master-1",
            AllocatedStorage=10,
            Engine="postgres",
            DBName="staging-postgres",
            DBInstanceClass="db.m1.small",
            PubliclyAccessible=True,
        )

        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access import (
                    rds_instance_no_public_access,
                )

                check = rds_instance_no_public_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is set as publicly accessible, but is not publicly exposed."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_public_with_public_sg(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
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
            PubliclyAccessible=True,
            VpcSecurityGroupIds=[default_sg_id],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider.audit_metadata.expected_checks = [
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port"
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.rds_client",
                new=RDS(aws_provider),
            ), mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.ec2_client",
                new=EC2(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access import (
                    rds_instance_no_public_access,
                )

                check = rds_instance_no_public_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"RDS Instance db-master-1 is set as publicly accessible and security group default ({default_sg_id}) has postgres port 5432 open to the Internet at endpoint db-master-1.aaaaaaaaaa.us-east-1.rds.amazonaws.com."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_rds_instance_public_with_filtered_sg(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "123.123.123.123/32"}],
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
            PubliclyAccessible=True,
            VpcSecurityGroupIds=[default_sg_id],
        )
        from prowler.providers.aws.services.rds.rds_service import RDS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access.rds_client",
                new=RDS(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.rds.rds_instance_no_public_access.rds_instance_no_public_access import (
                    rds_instance_no_public_access,
                )

                check = rds_instance_no_public_access()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "RDS Instance db-master-1 is set as publicly accessible but filtered with security groups."
                )
                assert result[0].resource_id == "db-master-1"
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:db-master-1"
                )
                assert result[0].resource_tags == []
