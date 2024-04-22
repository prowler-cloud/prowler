from unittest import mock

from boto3 import client, resource
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
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create IGW and attach to VPC
        igw = ec2.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)
        # Set IGW as default route for public subnet
        route_table = ec2.create_route_table(VpcId=vpc.id)
        route_table.associate_with_subnet(SubnetId=subnet.id)
        ec2_client.create_route(
            RouteTableId=route_table.id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw.id,
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                    if result.resource_id == vpc.id:
                        found = True
                        assert result.status == "FAIL"
                        assert (
                            result.status_extended
                            == f"VPC {vpc.id} has only public subnets."
                        )
                        assert result.resource_id == vpc.id
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION_US_EAST_1
                if not found:
                    assert False

    @mock_aws
    def test_vpc_subnet_private_and_public(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc.id,
            CidrBlock="10.0.0.0/17",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        route_table_private = ec2_client.create_route_table(
            VpcId=vpc.id,
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
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.128.0/17")
        # Create IGW and attach to VPC
        igw = ec2.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)
        # Set IGW as default route for public subnet
        route_table = ec2.create_route_table(VpcId=vpc.id)
        route_table.associate_with_subnet(SubnetId=subnet.id)
        ec2_client.create_route(
            RouteTableId=route_table.id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw.id,
        )

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                    if result.resource_id == vpc.id:
                        found = True
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"VPC {vpc.id} has private and public subnets."
                        )
                        assert result.resource_id == vpc.id
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION_US_EAST_1
                if not found:
                    assert False
