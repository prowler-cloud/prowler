from unittest import mock
from uuid import uuid4

from boto3 import client
from moto import mock_ec2

from prowler.providers.aws.services.vpc.vpc_service import VPC
from prowler.providers.aws.services.workspaces.workspaces_service import WorkSpace
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
WORKSPACE_ID = str(uuid4())
WORKSPACE_ARN = (
    f"arn:aws:workspaces:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:workspace/{WORKSPACE_ID}"
)


class Test_workspaces_vpc_2private_1public_subnets_nat:
    def test_no_workspaces(self):
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        vpc_client = mock.MagicMock
        vpc_client.vpcs = []
        with mock.patch(
            "prowler.providers.aws.services.workspaces.workspaces_service.WorkSpaces",
            workspaces_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                vpc_client,
            ):
                from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                    workspaces_vpc_2private_1public_subnets_nat,
                )

                check = workspaces_vpc_2private_1public_subnets_nat()
                result = check.execute()
                assert len(result) == 0

    def test_workspaces_no_subnet(self):
        workspaces_client = mock.MagicMock
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.vpc_client",
                new=VPC(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.workspaces_client",
                    new=workspaces_client,
                ):
                    from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                        workspaces_vpc_2private_1public_subnets_nat,
                    )

                    check = workspaces_vpc_2private_1public_subnets_nat()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Workspace {WORKSPACE_ID} is not in a private subnet or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached."
                    )
                    assert result[0].resource_id == WORKSPACE_ID
                    assert result[0].resource_arn == WORKSPACE_ARN
                    assert result[0].region == AWS_REGION

    @mock_ec2
    def test_workspaces_vpc_one_private_subnet(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
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
        # Workspace Mock
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id=subnet_private["Subnet"]["SubnetId"],
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.vpc_client",
                new=VPC(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.workspaces_client",
                    new=workspaces_client,
                ):
                    from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                        workspaces_vpc_2private_1public_subnets_nat,
                    )

                    check = workspaces_vpc_2private_1public_subnets_nat()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Workspace {WORKSPACE_ID} is not in a private subnet or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached."
                    )
                    assert result[0].resource_id == WORKSPACE_ID
                    assert result[0].resource_arn == WORKSPACE_ARN
                    assert result[0].region == AWS_REGION

    @mock_ec2
    def test_workspaces_vpc_two_private_subnet(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
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
        # VPC Private 2
        subnet_private_2 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.64/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )
        route_table_private_2 = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private_2["Subnet"]["SubnetId"],
        )
        # Workspace Mock
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id=subnet_private["Subnet"]["SubnetId"],
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.vpc_client",
                new=VPC(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.workspaces_client",
                    new=workspaces_client,
                ):
                    from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                        workspaces_vpc_2private_1public_subnets_nat,
                    )

                    check = workspaces_vpc_2private_1public_subnets_nat()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Workspace {WORKSPACE_ID} is not in a private subnet or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached."
                    )
                    assert result[0].resource_id == WORKSPACE_ID
                    assert result[0].resource_arn == WORKSPACE_ARN
                    assert result[0].region == AWS_REGION

    @mock_ec2
    def test_workspaces_vpc_two_private_subnet_one_public(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
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
        # VPC Private 2
        subnet_private_2 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.64/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )
        route_table_private_2 = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private_2["Subnet"]["SubnetId"],
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
        # Workspace Mock
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id=subnet_private["Subnet"]["SubnetId"],
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.vpc_client",
                new=VPC(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.workspaces_client",
                    new=workspaces_client,
                ):
                    from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                        workspaces_vpc_2private_1public_subnets_nat,
                    )

                    check = workspaces_vpc_2private_1public_subnets_nat()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Workspace {WORKSPACE_ID} is not in a private subnet or its VPC does not have 1 public subnet and 2 private subnets with a NAT Gateway attached."
                    )
                    assert result[0].resource_id == WORKSPACE_ID
                    assert result[0].resource_arn == WORKSPACE_ARN
                    assert result[0].region == AWS_REGION

    @mock_ec2
    def test_workspaces_vpc_two_private_subnet_one_public_and_nat(self):
        # EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION)
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        # VPC Private
        subnet_private = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.0/26",
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
        # VPC Private 2
        subnet_private_2 = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.64/26",
            AvailabilityZone=f"{AWS_REGION}a",
        )
        route_table_private_2 = ec2_client.create_route_table(
            VpcId=vpc["Vpc"]["VpcId"],
        )
        ec2_client.create_route(
            DestinationCidrBlock="10.10.10.0",
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
        )
        ec2_client.associate_route_table(
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
            SubnetId=subnet_private_2["Subnet"]["SubnetId"],
        )
        # Nat Gateway
        nat_gw = ec2_client.create_nat_gateway(
            SubnetId=subnet_private_2["Subnet"]["SubnetId"],
        )
        ec2_client.create_route(
            NatGatewayId=nat_gw["NatGateway"]["NatGatewayId"],
            RouteTableId=route_table_private_2["RouteTable"]["RouteTableId"],
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
        # Workspace Mock
        workspaces_client = mock.MagicMock
        workspaces_client.workspaces = []
        workspaces_client.workspaces.append(
            WorkSpace(
                id=WORKSPACE_ID,
                arn=WORKSPACE_ARN,
                region=AWS_REGION,
                user_volume_encryption_enabled=True,
                root_volume_encryption_enabled=True,
                subnet_id=subnet_private["Subnet"]["SubnetId"],
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.vpc_client",
                new=VPC(current_audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat.workspaces_client",
                    new=workspaces_client,
                ):
                    from prowler.providers.aws.services.workspaces.workspaces_vpc_2private_1public_subnets_nat.workspaces_vpc_2private_1public_subnets_nat import (
                        workspaces_vpc_2private_1public_subnets_nat,
                    )

                    check = workspaces_vpc_2private_1public_subnets_nat()
                    result = check.execute()
                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Workspace {WORKSPACE_ID} is in a private subnet within a VPC which has 1 public subnet 2 private subnets with a NAT Gateway attached."
                    )
                    assert result[0].resource_id == WORKSPACE_ID
                    assert result[0].resource_arn == WORKSPACE_ARN
                    assert result[0].region == AWS_REGION
