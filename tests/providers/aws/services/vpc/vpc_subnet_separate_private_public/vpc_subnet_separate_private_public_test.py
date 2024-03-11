from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_vpc_subnet_separate_private_public:
    @mock_aws
    def test_vpc_subnet_only_private(self):
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
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table_private = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private["Subnet"]["SubnetId"],
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public import (
                    vpc_subnet_separate_private_public,
                )

                check = vpc_subnet_separate_private_public()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == "VPC vpc_name has only private subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == [
                            {"Key": "Name", "Value": "vpc_name"}
                        ]
                        assert result.region == AWS_REGION_US_EAST_1
                if not found:
                    assert False

    @mock_aws
    def test_vpc_subnet_only_public(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Public
        subnet_public = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table_public = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        igw = ec2_client.create_internet_gateway()
        ec2_client.create_route(
            DestinationCidrBlock="0.0.0.0",
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            GatewayId=igw["InternetGateway"]["InternetGatewayId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            SubnetId=subnet_public["Subnet"]["SubnetId"],
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public import (
                    vpc_subnet_separate_private_public,
                )

                check = vpc_subnet_separate_private_public()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has only public subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION_US_EAST_1
                if not found:
                    assert False

    @mock_aws
    def test_vpc_subnet_private_and_public(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table_private = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private["Subnet"]["SubnetId"],
        )
        # VPC Public
        subnet_public = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table_public = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        igw = ec2_client.create_internet_gateway()
        ec2_client.create_route(
            DestinationCidrBlock="0.0.0.0",
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            GatewayId=igw["InternetGateway"]["InternetGatewayId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_public["RouteTable"]["RouteTableId"],
            SubnetId=subnet_public["Subnet"]["SubnetId"],
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public.vpc_client",
                new=VPC(current_audit_info),
            ):
                from prowler.providers.aws.services.vpc.vpc_subnet_separate_private_public.vpc_subnet_separate_private_public import (
                    vpc_subnet_separate_private_public,
                )

                check = vpc_subnet_separate_private_public()
                results = check.execute()

                found = False
                for result in results:
                    if result.resource_id == vpc["Vpc"]["VpcId"]:
                        found = True
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has private and public subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION_US_EAST_1
                if not found:
                    assert False
