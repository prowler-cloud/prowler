from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CREATION_TOKEN = "fs-123"


class Test_efs_mount_target_not_publicly_accessible:
    @mock_aws
    def test_efs_no_file_system(self):
        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible import (
                efs_mount_target_not_publicly_accessible,
            )

            check = efs_mount_target_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_efs_no_mount_target(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        from prowler.providers.aws.services.efs.efs_service import EFS

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible import (
                efs_mount_target_not_publicly_accessible,
            )

            check = efs_mount_target_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} does not have any public mount targets."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )

    @mock_aws
    def test_efs_mount_target_public_subnet(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        igw = ec2_client.create_internet_gateway()
        ec2_client.attach_internet_gateway(
            InternetGatewayId=igw["InternetGateway"]["InternetGatewayId"],
            VpcId=vpc["Vpc"]["VpcId"],
        )
        subnet_public = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table = ec2_client.create_route_table(VpcId=vpc["Vpc"]["VpcId"])
        ec2_client.create_route(
            RouteTableId=route_table["RouteTable"]["RouteTableId"],
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw["InternetGateway"]["InternetGatewayId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table["RouteTable"]["RouteTableId"],
            SubnetId=subnet_public["Subnet"]["SubnetId"],
        )
        mount_target = efs_client.create_mount_target(
            FileSystemId=file_system["FileSystemId"],
            SubnetId=subnet_public["Subnet"]["SubnetId"],
        )

        from prowler.providers.aws.services.efs.efs_service import EFS
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.vpc_client",
            new=VPC(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible import (
                efs_mount_target_not_publicly_accessible,
            )

            check = efs_mount_target_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} has public mount targets: {mount_target['MountTargetId']}"
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )

    @mock_aws
    def test_efs_mount_target_private_subnet(self):
        efs_client = client("efs", region_name=AWS_REGION_US_EAST_1)
        file_system = efs_client.create_file_system(CreationToken=CREATION_TOKEN)

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        efs_client.create_mount_target(
            FileSystemId=file_system["FileSystemId"],
            SubnetId=subnet_private["Subnet"]["SubnetId"],
        )

        from prowler.providers.aws.services.efs.efs_service import EFS
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.efs_client",
            new=EFS(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible.vpc_client",
            new=VPC(aws_provider),
        ):
            from prowler.providers.aws.services.efs.efs_mount_target_not_publicly_accessible.efs_mount_target_not_publicly_accessible import (
                efs_mount_target_not_publicly_accessible,
            )

            check = efs_mount_target_not_publicly_accessible()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"EFS {file_system['FileSystemId']} does not have any public mount targets."
            )
            assert result[0].resource_id == file_system["FileSystemId"]
            assert (
                result[0].resource_arn
                == f"arn:aws:elasticfilesystem:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:file-system/{file_system['FileSystemId']}"
            )
