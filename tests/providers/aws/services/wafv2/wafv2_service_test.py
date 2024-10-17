from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_WAFv2_Service:
    # Test WAFv2 Service
    @mock_aws
    def test_service(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.service == "wafv2"

    # Test WAFv2 Client
    @mock_aws
    def test_client(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        for regional_client in wafv2.regional_clients.values():
            assert regional_client.__class__.__name__ == "WAFV2"

    # Test WAFv2 Session
    @mock_aws
    def test__get_session__(self):
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert wafv2.session.__class__.__name__ == "Session"

    # Test WAFv2 Describe Regional Web ACLs
    @mock_aws
    def test_list_web_acls_regional(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
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
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_EU_WEST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # Test WAFv2 Describe Global Web ACLs
    @mock_aws
    def test_list_web_acls_global(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2.create_web_acl(
            Scope="CLOUDFRONT",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        wafv2 = WAFv2(aws_provider)
        assert len(wafv2.web_acls) == 1
        assert wafv2.web_acls[waf_arn].name == waf["Name"]
        assert wafv2.web_acls[waf_arn].region == AWS_REGION_US_EAST_1
        assert wafv2.web_acls[waf_arn].arn == waf["ARN"]
        assert wafv2.web_acls[waf_arn].id == waf["Id"]

    # Test WAFv2 Describe Web ACLs Resources
    @mock_aws
    def test_list_resources_for_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        conn = client("elbv2", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
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
        waf_arn = waf["ARN"]
        security_group = ec2.create_security_group(
            GroupName="a-security-group", Description="First One"
        )
        vpc = ec2.create_vpc(CidrBlock="172.28.7.0/24", InstanceTenancy="default")
        subnet1 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}a",
        )
        subnet2 = ec2.create_subnet(
            VpcId=vpc.id,
            CidrBlock="172.28.7.0/26",
            AvailabilityZone=f"{AWS_REGION_EU_WEST_1}b",
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
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws_provider)
        wafv2.web_acls[waf_arn].albs.append(lb["LoadBalancerArn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].albs) == 1
        assert lb["LoadBalancerArn"] in wafv2.web_acls[waf_arn].albs

    # Test WAFv2 describe Web user pools
    @mock_aws
    def test_list_resources_for_web_user_pools(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        cognito = client("cognito-idp", region_name=AWS_REGION_EU_WEST_1)
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
        waf_arn = waf["ARN"]
        user_pool = cognito.create_user_pool(PoolName="my-user-pool")["UserPool"]
        wafv2.associate_web_acl(WebACLArn=waf["ARN"], ResourceArn=user_pool["Arn"])
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        wafv2.web_acls[waf_arn].user_pools.append(user_pool["Arn"])
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].user_pools) == 1
        assert user_pool["Arn"] in wafv2.web_acls[waf_arn].user_pools

    @mock_aws
    def test_list_tags(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
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
        wafv2.tag_resource(
            ResourceARN=waf["ARN"], Tags=[{"Key": "Name", "Value": "my-web-acl"}]
        )
        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].tags) == 1
        assert wafv2.web_acls[waf_arn].tags[0]["Key"] == "Name"
        assert wafv2.web_acls[waf_arn].tags[0]["Value"] == "my-web-acl"

    @mock_aws
    def test_get_web_acl(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rule-on",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "idk",
            },
        )["Summary"]

        waf_arn = waf["ARN"]
        # WAFv2 client for this test class
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert len(wafv2.web_acls) == 1
        assert len(wafv2.web_acls[waf_arn].rules) == 1
        assert wafv2.web_acls[waf_arn].rules[0].name == "rule-on"
        assert wafv2.web_acls[waf_arn].rules[0].cloudwatch_metrics_enabled
