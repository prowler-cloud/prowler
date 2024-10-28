import json

import botocore
import mock
from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.vpc.vpc_service import VPC, Route
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeVpnConnections":
        return {
            "VpnConnections": [
                {
                    "VpnConnectionId": "vpn-1234567890abcdef0",
                    "CustomerGatewayId": "cgw-0123456789abcdef0",
                    "VpnGatewayId": "vgw-0123456789abcdef0",
                    "State": "available",
                    "Type": "ipsec.1",
                    "VgwTelemetry": [
                        {
                            "OutsideIpAddress": "192.168.1.1",
                            "Status": "UP",
                            "AcceptedRouteCount": 10,
                        },
                        {
                            "OutsideIpAddress": "192.168.1.2",
                            "Status": "UP",
                            "AcceptedRouteCount": 5,
                        },
                    ],
                    "Tags": [{"Key": "Name", "Value": "MyVPNConnection"}],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_VPC_Service:

    # Test VPC Service
    @mock_aws
    def test_service(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert vpc.service == "ec2"

    # Test VPC Client
    @mock_aws
    def test_client(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        for regional_client in vpc.regional_clients.values():
            assert regional_client.__class__.__name__ == "EC2"

    # Test VPC Session
    @mock_aws
    def test__get_session__(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert vpc.session.__class__.__name__ == "Session"

    # Test VPC Session
    @mock_aws
    def test_audited_account(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert vpc.audited_account == AWS_ACCOUNT_NUMBER

    # Test VPC Describe VPCs
    @mock_aws
    def test_describe_vpcs(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC
        vpc = ec2_client.create_vpc(
            CidrBlock="10.0.0.0/16",
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["Vpc"]
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert (
            len(vpc.vpcs) == 3
        )  # Number of AWS regions + created VPC, one default VPC per region
        for vpc in vpc.vpcs.values():
            if vpc.cidr_block == "10.0.0.0/16":
                assert vpc.tags == [
                    {"Key": "test", "Value": "test"},
                ]

    # Test VPC Describe Flow Logs
    @mock_aws
    def test_describe_flow_logs(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        new_vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]
        # Create VPC Flow log
        ec2_client.create_flow_logs(
            ResourceType="VPC",
            ResourceIds=[new_vpc["VpcId"]],
            TrafficType="ALL",
            LogDestinationType="cloud-watch-logs",
            LogGroupName="test_logs",
            DeliverLogsPermissionArn="arn:aws:iam::"
            + str(AWS_ACCOUNT_NUMBER)
            + ":role/test-role",
        )
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        # Search created VPC among default ones
        for vpc_iter in vpc.vpcs.values():
            if vpc_iter.id == new_vpc["VpcId"]:
                assert vpc_iter.flow_log is True

    # Test VPC Describe VPC Peering connections
    @mock_aws
    def test_describe_vpc_peering_connections(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPCs peers
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        peer_vpc = ec2_client.create_vpc(CidrBlock="11.0.0.0/16")
        vpc_pcx = ec2_client.create_vpc_peering_connection(
            VpcId=vpc["Vpc"]["VpcId"],
            PeerVpcId=peer_vpc["Vpc"]["VpcId"],
            TagSpecifications=[
                {
                    "ResourceType": "vpc-peering-connection",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )
        vpc_pcx_id = vpc_pcx["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        vpc_pcx = ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_pcx_id
        )
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert len(vpc.vpc_peering_connections) == 1
        assert vpc.vpc_peering_connections[0].id == vpc_pcx_id
        assert vpc.vpc_peering_connections[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test VPC Describe VPC Peering connections
    @mock_aws
    def test__describe_route_tables__(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        _ = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create VPCs peers as well as a route
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        peer_vpc = ec2_client.create_vpc(CidrBlock="11.0.0.0/16")
        vpc_pcx = ec2_client.create_vpc_peering_connection(
            VpcId=vpc["Vpc"]["VpcId"], PeerVpcId=peer_vpc["Vpc"]["VpcId"]
        )
        vpc_pcx_id = vpc_pcx["VpcPeeringConnection"]["VpcPeeringConnectionId"]

        vpc_pcx = ec2_client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=vpc_pcx_id
        )
        main_route_table_id = ec2_client.describe_route_tables(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc["Vpc"]["VpcId"]]},
                {"Name": "association.main", "Values": ["true"]},
            ]
        )["RouteTables"][0]["RouteTableId"]
        # FilterNotImplementedError: The filter 'route.vpc-peering-connection-id' for DescribeRouteTables has not been implemented in Moto yet.
        # main_route_table = ec2_resource.RouteTable(main_route_table_id)
        # main_route_table.create_route(
        #     DestinationCidrBlock="10.0.0.4/24", VpcPeeringConnectionId=vpc_pcx_id
        # )

        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        vpc.vpc_peering_connections[0].route_tables = [
            Route(
                id=main_route_table_id,
                destination_cidrs=["10.0.0.4/24"],
            )
        ]
        assert len(vpc.vpc_peering_connections[0].route_tables) == 1
        assert vpc.vpc_peering_connections[0].id == vpc_pcx_id

    # Test VPC Describe VPC Endpoints
    @mock_aws
    def test_describe_vpc_endpoints(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC endpoint
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]

        route_table = ec2_client.create_route_table(VpcId=vpc["VpcId"])["RouteTable"]
        endpoint = ec2_client.create_vpc_endpoint(
            VpcId=vpc["VpcId"],
            ServiceName="com.amazonaws.us-east-1.s3",
            RouteTableIds=[route_table["RouteTableId"]],
            VpcEndpointType="Gateway",
            PolicyDocument=json.dumps(
                {
                    "Statement": [
                        {
                            "Action": "*",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Resource": "*",
                        }
                    ]
                }
            ),
            TagSpecifications=[
                {
                    "ResourceType": "vpc-endpoint",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["VpcEndpoint"]["VpcEndpointId"]
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert len(vpc.vpc_endpoints) == 1
        assert vpc.vpc_endpoints[0].id == endpoint
        assert vpc.vpc_endpoints[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert vpc.vpc_endpoints[0].type == "Gateway"

    # Test VPC Describe VPC Endpoint Services
    @mock_aws
    def test_describe_vpc_endpoint_services(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn],
            TagSpecifications=[
                {
                    "ResourceType": "vpc-endpoint-service-configuration",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )
        endpoint_id = endpoint["ServiceConfiguration"]["ServiceId"]
        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"
        endpoint_service = endpoint["ServiceConfiguration"]["ServiceName"]

        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)

        for vpce in vpc.vpc_endpoint_services:
            assert vpce.arn == endpoint_arn
            assert vpce.id == endpoint_id
            assert vpce.service == endpoint_service
            assert vpce.owner_id == AWS_ACCOUNT_NUMBER
            assert vpce.allowed_principals == []
            assert vpce.region == AWS_REGION_US_EAST_1
            assert vpce.tags == []

    # Test VPC Describe VPC Subnets
    @mock_aws
    def test_describe_vpc_subnets(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        default_sg = ec2_client.describe_security_groups(GroupNames=["default"])[
            "SecurityGroups"
        ][0]
        default_sg_id = default_sg["GroupId"]
        ec2_client.authorize_security_group_ingress(
            GroupId=default_sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 389,
                    "ToPort": 389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
        subnet_id = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.0.0/16",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )["Subnet"]["SubnetId"]
        # add default route of subnet to an internet gateway to make it public
        igw_id = ec2_client.create_internet_gateway()["InternetGateway"][
            "InternetGatewayId"
        ]
        # attach internet gateway to subnet
        ec2_client.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        # create route table
        route_table_id = ec2_client.create_route_table(VpcId=vpc_id)["RouteTable"][
            "RouteTableId"
        ]
        # associate route table with subnet
        ec2_client.associate_route_table(
            RouteTableId=route_table_id, SubnetId=subnet_id
        )
        # add route to route table
        ec2_client.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock="0.0.0.0/0",
            GatewayId=igw_id,
        )
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert (
            len(vpc.vpcs) == 3
        )  # Number of AWS regions + created VPC, one default VPC per region
        for vpc in vpc.vpcs.values():
            if vpc.cidr_block == "10.0.0.0/16":
                assert vpc.subnets[0].id == subnet_id
                assert vpc.subnets[0].default is False
                assert vpc.subnets[0].vpc_id == vpc_id
                assert vpc.subnets[0].cidr_block == "10.0.0.0/16"
                assert vpc.subnets[0].availability_zone == f"{AWS_REGION_US_EAST_1}a"
                assert vpc.subnets[0].public
                assert vpc.subnets[0].nat_gateway is False
                assert vpc.subnets[0].region == AWS_REGION_US_EAST_1
                assert vpc.subnets[0].tags is None

    @mock_aws
    def test_vpc_subnet_with_open_nacl(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC
        vpc_id = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
        subnet_id = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.0.0.0/16",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )["Subnet"]["SubnetId"]
        nacl_id = ec2_client.create_network_acl(VpcId=vpc_id)["NetworkAcl"][
            "NetworkAclId"
        ]
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=100,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )
        ec2_client.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=200,
            Protocol="-1",
            RuleAction="allow",
            Egress=True,
            CidrBlock="0.0.0.0/0",
        )
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        vpc = VPC(aws_provider)
        assert (
            len(vpc.vpcs) == 3
        )  # Number of AWS regions + created VPC, one default VPC per region
        for vpc in vpc.vpcs.values():
            if vpc.cidr_block == "10.0.0.0/16":
                assert vpc.subnets[0].id == subnet_id
                assert vpc.subnets[0].vpc_id == vpc_id
                assert vpc.subnets[0].availability_zone == f"{AWS_REGION_US_EAST_1}a"
                assert vpc.subnets[0].region == AWS_REGION_US_EAST_1

    # Test VPC Describe VPN Connections
    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_describe_vpn_connections(self):
        # Generate VPC Client

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        vpc = VPC(aws_provider)

        vpn_arn = f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:vpn-connection/vpn-1234567890abcdef0"
        assert len(vpc.vpn_connections) == 1
        assert vpn_arn in vpc.vpn_connections
        vpn_conn = vpc.vpn_connections[vpn_arn]
        assert vpn_conn.id == "vpn-1234567890abcdef0"
        assert vpn_conn.region == AWS_REGION_US_EAST_1
        assert len(vpn_conn.tunnels) == 2
