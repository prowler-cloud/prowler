from boto3 import client, resource, session
from moto import mock_ec2, mock_elbv2, mock_wafv2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_WAFv2_Service:
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    # Test WAFv2 Service
    @mock_wafv2
    def test_service(self):
        # WAFv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        wafv2 = WAFv2(audit_info)
        assert wafv2.service == "wafv2"

    # Test WAFv2 Client
    @mock_wafv2
    def test_client(self):
        # WAFv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        wafv2 = WAFv2(audit_info)
        for regional_client in wafv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFV2"

    # Test WAFv2 Session
    @mock_wafv2
    def test__get_session__(self):
        # WAFv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        wafv2 = WAFv2(audit_info)
        assert wafv2.session.__class__.__name__ == "Session"

    # Test WAFv2 Describe Web ACLs
    @mock_wafv2
    def test__list_web_acls__(self):
        wafv2 = client("wafv2", region_name="us-east-1")
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        # WAFv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        wafv2 = WAFv2(audit_info)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[0].name == waf["Name"]
        assert wafv2.web_acls[0].region == AWS_REGION
        assert wafv2.web_acls[0].arn == waf["ARN"]
        assert wafv2.web_acls[0].id == waf["Id"]

    # Test WAFv2 Describe Web ACLs Resources
    @mock_ec2
    @mock_elbv2
    @mock_wafv2
    def test__list_resources_for_web_acl__(self):
        wafv2 = client("wafv2", region_name="us-east-1")
        conn = client("elbv2", region_name=AWS_REGION)
        ec2 = resource("ec2", region_name=AWS_REGION)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
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
            Type="application",
        )["LoadBalancers"][0]

        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=lb["LoadBalancerArn"])
        # WAFv2 client for this test class
        audit_info = self.set_mocked_audit_info()
        wafv2 = WAFv2(audit_info)
        wafv2.web_acls[0].albs.append(lb["LoadBalancerArn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[0].albs) == 1
        assert lb["LoadBalancerArn"] in wafv2.web_acls[0].albs
