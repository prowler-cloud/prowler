from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_vpc_endpoint_for_multi_az:
    @mock_aws
    def test_vpc_no_endpoints(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled import (
                    vpc_endpoint_multi_az_enabled,
                )

                check = vpc_endpoint_multi_az_enabled()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_no_multi_az_endpoint(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24",
            InstanceTenancy="default",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": "vpc_name"},
                    ],
                },
            ],
        )["Vpc"]
        # VPC AZ 1
        subnet_one = ec2_client.create_subnet(
            VpcId=vpc["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )["Subnet"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.vpce.us-east-1.ssmmessages",
            RouteTableIds=[route_table["RouteTableId"]],
            SubnetIds=[subnet_one["SubnetId"]],
            VpcEndpointType="Interface",
        )["VpcEndpoint"]
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled import (
                    vpc_endpoint_multi_az_enabled,
                )

                check = vpc_endpoint_multi_az_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"VPC Endpoint {vpc_endpoint['VpcEndpointId']} in VPC {vpc['VpcId']} has subnets in different AZs."
                )
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc-endpoint/{vpc_endpoint['VpcEndpointId']}"
                )

    @mock_aws
    def test_vpc_endpoint_multi_az_enabled(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24",
            InstanceTenancy="default",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "Name", "Value": "vpc_name"},
                    ],
                },
            ],
        )["Vpc"]
        # VPC AZ 1
        subnet_one = ec2_client.create_subnet(
            VpcId=vpc["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )["Subnet"]

        # VPC AZ 2
        subnet_two = ec2_client.create_subnet(
            VpcId=vpc["VpcId"],
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}b",
        )["Subnet"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        vpc_endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.vpce.us-east-1.ssmmessages",
            RouteTableIds=[route_table["RouteTableId"]],
            SubnetIds=[subnet_one["SubnetId"], subnet_two["SubnetId"]],
            VpcEndpointType="Interface",
        )["VpcEndpoint"]

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_multi_az_enabled.vpc_endpoint_multi_az_enabled import (
                    vpc_endpoint_multi_az_enabled,
                )

                check = vpc_endpoint_multi_az_enabled()
                result = check.execute()

                assert len(result) == 1
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Endpoint {vpc_endpoint['VpcEndpointId']} in VPC {vpc['VpcId']} does not have subnets in different AZs."
                )
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:vpc-endpoint/{vpc_endpoint['VpcEndpointId']}"
                )
