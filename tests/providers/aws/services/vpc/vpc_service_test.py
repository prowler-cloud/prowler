import json

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.vpc.vpc_service import VPC, Route
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_VPC_Service:

    # Test VPC Service
    @mock_aws
    def test_service(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        vpc = VPC(aws_provider)
        assert vpc.service == "ec2"

    # Test VPC Client
    @mock_aws
    def test_client(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
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
        vpc = VPC(aws_provider)
        assert vpc.session.__class__.__name__ == "Session"

    # Test VPC Session
    @mock_aws
    def test_audited_account(self):
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        vpc = VPC(aws_provider)
        assert vpc.audited_account == AWS_ACCOUNT_NUMBER

    # Test VPC Describe VPCs
    @mock_aws
    def test__describe_vpcs__(self):
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
    def test__describe_flow_logs__(self):
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
        vpc = VPC(aws_provider)
        # Search created VPC among default ones
        for vpc_iter in vpc.vpcs.values():
            if vpc_iter.id == new_vpc["VpcId"]:
                assert vpc_iter.flow_log is True

    # Test VPC Describe VPC Peering connections
    @mock_aws
    def test__describe_vpc_peering_connections__(self):
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
    def test__describe_vpc_endpoints__(self):
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
        vpc = VPC(aws_provider)
        assert len(vpc.vpc_endpoints) == 1
        assert vpc.vpc_endpoints[0].id == endpoint
        assert vpc.vpc_endpoints[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test VPC Describe VPC Endpoint Services
    @mock_aws
    def test__describe_vpc_endpoint_services__(self):
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
    def test__describe_vpc_subnets__(self):
        # Generate VPC Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create VPC
        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        # VPC client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1]
        )
        vpc = VPC(aws_provider)
        assert (
            len(vpc.vpcs) == 3
        )  # Number of AWS regions + created VPC, one default VPC per region
        for vpc in vpc.vpcs.values():
            if vpc.cidr_block == "172.28.7.0/24":
                assert vpc.subnets[0].id == subnet["Subnet"]["SubnetId"]
                assert vpc.subnets[0].default is False
                assert vpc.subnets[0].vpc_id == vpc.id
                assert vpc.subnets[0].cidr_block == "172.28.7.192/26"
                assert vpc.subnets[0].availability_zone == f"{AWS_REGION_US_EAST_1}a"
                assert vpc.subnets[0].public is False
                assert vpc.subnets[0].nat_gateway is False
                assert vpc.subnets[0].region == AWS_REGION_US_EAST_1
                assert vpc.subnets[0].tags is None
