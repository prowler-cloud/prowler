from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_1_AZA,
    AWS_REGION_EU_WEST_1_AZB,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ELBv2_Service:
    # Test ELBv2 Service
    @mock_aws
    def test_service(self):
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert elbv2.service == "elbv2"

    # Test ELBv2 Client
    @mock_aws
    def test_client(self):
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        for regional_client in elbv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "ElasticLoadBalancingv2"

    # Test ELBv2 Session
    @mock_aws
    def test__get_session__(self):
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert elbv2.session.__class__.__name__ == "Session"

    # Test ELBv2 Describe Load Balancers
    @mock_aws
    def test_describe_load_balancers(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert len(elbv2.loadbalancersv2) == 1
        assert lb["LoadBalancerArn"] in elbv2.loadbalancersv2.keys()
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].name == "my-lb"
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].region == AWS_REGION_EU_WEST_1
        )
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].scheme == "internal"
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].type == "application"
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].listeners == {}
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].dns
            == "my-lb-1.eu-west-1.elb.amazonaws.com"
        )
        assert len(elbv2.loadbalancersv2[lb["LoadBalancerArn"]].availability_zones) == 2
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].availability_zones[
                AWS_REGION_EU_WEST_1_AZA
            ]
            == subnet1.id
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].availability_zones[
                AWS_REGION_EU_WEST_1_AZB
            ]
            == subnet2.id
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].security_groups[0]
            == security_group.id
        )

    # Test ELBv2 Describe Listeners
    @mock_aws
    def test_describe_listeners(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]

        listener_arn = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            Port=443,
            DefaultActions=[
                {
                    "Type": "redirect",
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                        "Port": "443",
                        "StatusCode": "HTTP_301",
                    },
                }
            ],
        )["Listeners"][0]["ListenerArn"]
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert len(elbv2.loadbalancersv2[lb["LoadBalancerArn"]].listeners) == 1
        assert listener_arn in elbv2.loadbalancersv2[lb["LoadBalancerArn"]].listeners
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].listeners[listener_arn].region
            == AWS_REGION_EU_WEST_1
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]]
            .listeners[listener_arn]
            .protocol
            == "HTTP"
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].listeners[listener_arn].port
            == 443
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]]
            .listeners[listener_arn]
            .ssl_policy
            == "ELBSecurityPolicy-2016-08"
        )

    # Test ELBv2 Describe Load Balancers Attributes
    @mock_aws
    def test_describe_load_balancer_attributes(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]

        conn.modify_load_balancer_attributes(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Attributes=[
                {"Key": "routing.http.desync_mitigation_mode", "Value": "defensive"},
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "load_balancing.cross_zone.enabled", "Value": "true"},
                {"Key": "deletion_protection.enabled", "Value": "true"},
                {
                    "Key": "routing.http.drop_invalid_header_fields.enabled",
                    "Value": "false",
                },
            ],
        )
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert len(elbv2.loadbalancersv2) == 1
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].desync_mitigation_mode
            == "defensive"
        )
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].access_logs == "true"
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].deletion_protection == "true"
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].cross_zone_load_balancing
            == "true"
        )
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].drop_invalid_header_fields
            == "false"
        )

    # Test ELBv2 Describe Load Balancers Attributes
    @mock_aws
    def test_describe_rules(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]

        actions = [
            {
                "Type": "redirect",
                "RedirectConfig": {
                    "Protocol": "HTTPS",
                    "Port": "443",
                    "StatusCode": "HTTP_301",
                },
            }
        ]
        listener_arn = conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=actions,
        )["Listeners"][0]["ListenerArn"]
        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )
        elbv2 = ELBv2(aws_provider)
        assert len(elbv2.loadbalancersv2) == 1
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]]
            .listeners[listener_arn]
            .rules[0]
            .actions
            == actions
        )

    # Test ELBv2 Describe Tags
    @mock_aws
    def test_describe_tags(self):
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZA,
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=AWS_REGION_EU_WEST_1_AZB,
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]

        conn.add_tags(
            ResourceArns=[lb["LoadBalancerArn"]],
            Tags=[
                {"Key": "Name", "Value": "my-lb"},
                {"Key": "Environment", "Value": "dev"},
            ],
        )

        # ELBv2 client for this test class
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        elbv2 = ELBv2(aws_provider)

        assert len(elbv2.loadbalancersv2) == 1
        assert len(elbv2.loadbalancersv2[lb["LoadBalancerArn"]].tags) == 2
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].tags[0]["Key"] == "Name"
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].tags[0]["Value"] == "my-lb"
        assert (
            elbv2.loadbalancersv2[lb["LoadBalancerArn"]].tags[1]["Key"] == "Environment"
        )
        assert elbv2.loadbalancersv2[lb["LoadBalancerArn"]].tags[1]["Value"] == "dev"
