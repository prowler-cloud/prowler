from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_vpc_subnet_no_public_ip_by_default:
    @mock_aws
    def test_vpc_with_map_ip_on_launch(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": "subnet_name"},
                    ],
                },
            ],
        )

        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_private["Subnet"]["SubnetId"],
            MapPublicIpOnLaunch={"Value": True},
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default import (
                    vpc_subnet_no_public_ip_by_default,
                )

                check = vpc_subnet_no_public_ip_by_default()
                results = check.execute()

                for result in results:
                    if result.resource_id == subnet_private["Subnet"]["SubnetId"]:
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == "VPC subnet subnet_name assigns public IP by default."
                        )

    @mock_aws
    def test_vpc_without_map_ip_on_launch(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )

        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_private["Subnet"]["SubnetId"],
            MapPublicIpOnLaunch={"Value": False},
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default import (
                    vpc_subnet_no_public_ip_by_default,
                )

                check = vpc_subnet_no_public_ip_by_default()
                results = check.execute()

                for result in results:
                    if result.resource_id == subnet_private["Subnet"]["SubnetId"]:
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"VPC subnet {subnet_private['Subnet']['SubnetId']} does NOT assign public IP by default."
                        )

    @mock_aws
    def test_vpc_with_map_ip_on_launch_but_unused(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
            TagSpecifications=[
                {
                    "ResourceType": "subnet",
                    "Tags": [
                        {"Key": "Name", "Value": "subnet_name"},
                    ],
                },
            ],
        )

        ec2_client.modify_subnet_attribute(
            SubnetId=subnet_private["Subnet"]["SubnetId"],
            MapPublicIpOnLaunch={"Value": True},
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_US_EAST_1], scan_unused_services=False
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default.vpc_client",
                new=VPC(aws_provider),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_no_public_ip_by_default.vpc_subnet_no_public_ip_by_default import (
                    vpc_subnet_no_public_ip_by_default,
                )

                check = vpc_subnet_no_public_ip_by_default()
                results = check.execute()

                assert len(results) == 0
