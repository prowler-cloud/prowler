from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.elb.elb_service import ELB
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ELB_Service:
    # Test ELB Service
    @mock_aws
    def test_service(self):
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert elb.service == "elb"

    # Test ELB Client
    @mock_aws
    def test_client(self):
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        for regional_client in elb.regional_clients.values():
            assert regional_client.__class__.__name__ == "ElasticLoadBalancing"

    # Test ELB Session
    @mock_aws
    def test__get_session__(self):
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert elb.session.__class__.__name__ == "Session"

    # Test ELB Describe Load Balancers
    @mock_aws
    def test__describe_load_balancers__(self):
        elb = client("elb", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION_US_EAST_1}a"],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert len(elb.loadbalancers) == 1
        assert elb.loadbalancers[0].name == "my-lb"
        assert elb.loadbalancers[0].region == AWS_REGION_US_EAST_1
        assert elb.loadbalancers[0].scheme == "internal"
        assert (
            elb.loadbalancers[0].arn
            == f"arn:aws:elasticloadbalancing:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
        )

    # Test ELB Describe Load Balancers Attributes
    @mock_aws
    def test__describe_load_balancer_attributes__(self):
        elb = client("elb", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {"Protocol": "tcp", "LoadBalancerPort": 80, "InstancePort": 8080},
                {"Protocol": "http", "LoadBalancerPort": 81, "InstancePort": 9000},
            ],
            AvailabilityZones=[f"{AWS_REGION_US_EAST_1}a"],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )

        elb.modify_load_balancer_attributes(
            LoadBalancerName="my-lb",
            LoadBalancerAttributes={
                "AccessLog": {
                    "Enabled": True,
                    "S3BucketName": "mb",
                    "EmitInterval": 42,
                    "S3BucketPrefix": "s3bf",
                }
            },
        )
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert elb.loadbalancers[0].name == "my-lb"
        assert elb.loadbalancers[0].region == AWS_REGION_US_EAST_1
        assert elb.loadbalancers[0].scheme == "internal"
        assert elb.loadbalancers[0].access_logs
        assert (
            elb.loadbalancers[0].arn
            == f"arn:aws:elasticloadbalancing:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
        )
