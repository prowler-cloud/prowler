from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.elb.elb_service import ELB
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
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
    def test_describe_load_balancers(self):
        elb = client("elb", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        acm = client("acm", region_name=AWS_REGION_US_EAST_1)
        certificate = acm.request_certificate(DomainName="www.example.com")
        security_group = ec2.create_security_group(
            GroupName="sg01", Description="Test security group sg01"
        )

        dns_name = elb.create_load_balancer(
            LoadBalancerName="my-lb",
            Listeners=[
                {
                    "Protocol": "tcp",
                    "LoadBalancerPort": 80,
                    "InstancePort": 8080,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
                {
                    "Protocol": "http",
                    "LoadBalancerPort": 81,
                    "InstancePort": 9000,
                    "SSLCertificateId": certificate["CertificateArn"],
                },
            ],
            AvailabilityZones=[AWS_REGION_US_EAST_1_AZA],
            Scheme="internal",
            SecurityGroups=[security_group.id],
        )["DNSName"]
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert len(elb.loadbalancers) == 1
        assert elb.loadbalancers[elb_arn].name == "my-lb"
        assert elb.loadbalancers[elb_arn].region == AWS_REGION_US_EAST_1
        assert elb.loadbalancers[elb_arn].scheme == "internal"
        assert elb.loadbalancers[elb_arn].dns == dns_name
        assert len(elb.loadbalancers[elb_arn].listeners) == 2
        assert elb.loadbalancers[elb_arn].listeners[0].protocol == "TCP"
        assert elb.loadbalancers[elb_arn].listeners[0].policies == []
        assert (
            elb.loadbalancers[elb_arn].listeners[0].certificate_arn
            == certificate["CertificateArn"]
        )
        assert elb.loadbalancers[elb_arn].listeners[1].protocol == "HTTP"
        assert elb.loadbalancers[elb_arn].listeners[1].policies == []
        assert (
            elb.loadbalancers[elb_arn].listeners[0].certificate_arn
            == certificate["CertificateArn"]
        )
        assert len(elb.loadbalancers[elb_arn].availability_zones) == 1
        assert AWS_REGION_US_EAST_1_AZA in elb.loadbalancers[elb_arn].availability_zones

    # Test ELB Describe Load Balancers Attributes
    @mock_aws
    def test_describe_load_balancer_attributes(self):
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
                },
                "CrossZoneLoadBalancing": {"Enabled": True},
                "ConnectionDraining": {"Enabled": True, "Timeout": 60},
            },
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert elb.loadbalancers[elb_arn].name == "my-lb"
        assert elb.loadbalancers[elb_arn].region == AWS_REGION_US_EAST_1
        assert elb.loadbalancers[elb_arn].scheme == "internal"
        assert elb.loadbalancers[elb_arn].access_logs
        assert elb.loadbalancers[elb_arn].cross_zone_load_balancing
        assert elb.loadbalancers[elb_arn].connection_draining
        assert elb.loadbalancers[elb_arn].desync_mitigation_mode is None

    # Test ELB Describe Tags
    @mock_aws
    def test_describe_tags(self):
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

        elb.add_tags(
            LoadBalancerNames=["my-lb"],
            Tags=[
                {"Key": "key1", "Value": "value1"},
                {"Key": "key2", "Value": "value2"},
            ],
        )
        elb_arn = f"arn:aws:elasticloadbalancing:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:loadbalancer/my-lb"
        # ELB client for this test class
        aws_provider = set_mocked_aws_provider()
        elb = ELB(aws_provider)
        assert elb.loadbalancers[elb_arn].name == "my-lb"
        assert elb.loadbalancers[elb_arn].region == AWS_REGION_US_EAST_1
        assert elb.loadbalancers[elb_arn].scheme == "internal"
        assert len(elb.loadbalancers[elb_arn].tags) == 2
        assert elb.loadbalancers[elb_arn].tags[0]["Key"] == "key1"
        assert elb.loadbalancers[elb_arn].tags[0]["Value"] == "value1"
        assert elb.loadbalancers[elb_arn].tags[1]["Key"] == "key2"
        assert elb.loadbalancers[elb_arn].tags[1]["Value"] == "value2"
