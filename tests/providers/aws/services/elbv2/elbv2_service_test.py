from boto3 import client, resource, session
from moto import mock_ec2, mock_elbv2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.elbv2.elbv2_service import ELBv2

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_ELBv2_Service:
    # Mocked Audit Info
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
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Test ELBv2 Service
    @mock_elbv2
    def test_service(self):
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert elbv2.service == "elbv2"

    # Test ELBv2 Client
    @mock_elbv2
    def test_client(self):
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        for regional_client in elbv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "ElasticLoadBalancingv2"

    # Test ELBv2 Session
    @mock_elbv2
    def test__get_session__(self):
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert elbv2.session.__class__.__name__ == "Session"

    # Test ELBv2 Describe Load Balancers
    @mock_ec2
    @mock_elbv2
    def test__describe_load_balancers__(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert len(elbv2.loadbalancersv2) == 1
        assert elbv2.loadbalancersv2[0].name == "my-lb"
        assert elbv2.loadbalancersv2[0].region == AWS_REGION
        assert elbv2.loadbalancersv2[0].scheme == "internal"
        assert elbv2.loadbalancersv2[0].arn == lb["LoadBalancerArn"]

    # Test ELBv2 Describe Listeners
    @mock_ec2
    @mock_elbv2
    def test__describe_listeners__(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
        )

        lb = conn.create_load_balancer(
            Name="my-lb",
            Subnets=[subnet1.id, subnet2.id],
            SecurityGroups=[security_group.id],
            Scheme="internal",
        )["LoadBalancers"][0]

        conn.create_listener(
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
        )
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert len(elbv2.loadbalancersv2[0].listeners) == 1
        assert elbv2.loadbalancersv2[0].listeners[0].protocol == "HTTP"
        assert elbv2.loadbalancersv2[0].listeners[0].port == 443

    # Test ELBv2 Describe Load Balancers Attributes
    @mock_ec2
    @mock_elbv2
    def test__describe_load_balancer_attributes__(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
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
                {"Key": "deletion_protection.enabled", "Value": "true"},
                {
                    "Key": "routing.http.drop_invalid_header_fields.enabled",
                    "Value": "false",
                },
            ],
        )
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert len(elbv2.loadbalancersv2) == 1
        assert elbv2.loadbalancersv2[0].desync_mitigation_mode == "defensive"
        assert elbv2.loadbalancersv2[0].access_logs == "true"
        assert elbv2.loadbalancersv2[0].deletion_protection == "true"
        assert elbv2.loadbalancersv2[0].drop_invalid_header_fields == "false"

    # Test ELBv2 Describe Load Balancers Attributes
    @mock_ec2
    @mock_elbv2
    def test__describe_rules__(self):
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)

        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.192/26", AvailabilityZone=f"{AWS_REGION}a"
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id, CidrBlock="172.28.7.0/26", AvailabilityZone=f"{AWS_REGION}b"
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
        conn.create_listener(
            LoadBalancerArn=lb["LoadBalancerArn"],
            Protocol="HTTP",
            DefaultActions=actions,
        )
        # ELBv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        elbv2 = ELBv2(audit_info)
        assert len(elbv2.loadbalancersv2) == 1
        assert elbv2.loadbalancersv2[0].listeners[0].rules[0].actions == actions
