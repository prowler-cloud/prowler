from unittest import mock

from boto3 import client, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_vpc_subnet_separate_private_public:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )

        return audit_info

    @mock_ec2
    def test_vpc_subnet_only_private(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
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

        current_audit_info = self.set_mocked_audit_info()

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
                            == f"VPC {vpc['Vpc']['VpcId']} has only private subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False

    @mock_ec2
    def test_vpc_subnet_only_public(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Public
        subnet_public = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
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

        current_audit_info = self.set_mocked_audit_info()

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
                            == f"VPC {vpc['Vpc']['VpcId']} has only public subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False

    @mock_ec2
    def test_vpc_subnet_private_and_public(self):
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION}a",
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
            AvailabilityZone=f"{AWS_REGION}a",
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

        current_audit_info = self.set_mocked_audit_info()

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
                        assert result.status == "PASS"
                        assert (
                            result.status_extended
                            == f"VPC {vpc['Vpc']['VpcId']} has private and public subnets."
                        )
                        assert result.resource_id == vpc["Vpc"]["VpcId"]
                        assert result.resource_tags == []
                        assert result.region == AWS_REGION
                if not found:
                    assert False
