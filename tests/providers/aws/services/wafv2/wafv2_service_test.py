from unittest.mock import patch

import botocore
from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2
from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

WEB_ACL_VISIBILITY_CONFIG = {
    "SampledRequestsEnabled": False,
    "CloudWatchMetricsEnabled": False,
    "MetricName": "idk",
}


def _managed_rule_group_rule(name, priority, override_action):
    """Web ACL rule referencing an AWS managed rule group."""
    return {
        "Name": f"AWS-{name}",
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": name}},
        "OverrideAction": {override_action: {}},
        "VisibilityConfig": {
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name,
        },
    }


def _client_error(operation_name):
    return botocore.exceptions.ClientError(
        {
            "Error": {
                "Code": "AccessDeniedException",
                "Message": f"User is not authorized to perform wafv2:{operation_name}",
            }
        },
        operation_name,
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
                },
                {
                    "Name": "AWS-AWSManagedRulesPHPRuleSet",
                    "Priority": 2,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesPHPRuleSet",
                            "Version": "Version_2.3",
                        }
                    },
                    "OverrideAction": {"None": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "php-rule-set",
                    },
                },
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
        assert len(wafv2.web_acls[waf_arn].rules) == 2
        assert wafv2.web_acls[waf_arn].rules[0].name == "rule-on"
        assert wafv2.web_acls[waf_arn].rules[0].cloudwatch_metrics_enabled
        assert wafv2.web_acls[waf_arn].rules[0].managed_rule_group is None
        managed = wafv2.web_acls[waf_arn].rules[1].managed_rule_group
        assert managed.vendor_name == "AWS"
        assert managed.name == "AWSManagedRulesPHPRuleSet"
        assert managed.version == "Version_2.3"

    @mock_aws
    def test_get_web_acl_override_action(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rule-on",
                    "Priority": 0,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "web-acl-test-metric",
                    },
                },
                {
                    "Name": "AWS-AWSManagedRulesSQLiRuleSet",
                    "Priority": 1,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesSQLiRuleSet",
                            "Version": "Version_2.0",
                            "ExcludedRules": [{"Name": "SQLi_QUERYARGUMENTS"}],
                            "ScopeDownStatement": {
                                "ByteMatchStatement": {
                                    "SearchString": "/api",
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [
                                        {"Type": "NONE", "Priority": 0}
                                    ],
                                    "PositionalConstraint": "STARTS_WITH",
                                }
                            },
                            "RuleActionOverrides": [
                                {"Name": "SQLi_BODY", "ActionToUse": {"Count": {}}}
                            ],
                        }
                    },
                    "OverrideAction": {"None": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "AWSManagedRulesSQLiRuleSet",
                    },
                },
                _managed_rule_group_rule(
                    "AWSManagedRulesKnownBadInputsRuleSet", 2, "Count"
                ),
            ],
            VisibilityConfig=WEB_ACL_VISIBILITY_CONFIG,
        )["Summary"]

        waf_arn = waf["ARN"]
        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        wafv2 = WAFv2(aws)
        assert wafv2.web_acls_list_failed_scopes == set()
        web_acl = wafv2.web_acls[waf_arn]
        assert web_acl.rules_retrieved
        assert len(web_acl.rules) == 3
        assert web_acl.rules[0].managed_rule_group is None
        assert web_acl.rules[0].overridden_to_count is False
        sqli = web_acl.rules[1].managed_rule_group
        assert sqli.vendor_name == "AWS"
        assert sqli.name == "AWSManagedRulesSQLiRuleSet"
        assert sqli.version == "Version_2.0"
        assert sqli.rule_action_overrides == {"SQLi_BODY": "Count"}
        assert sqli.excluded_rules == ["SQLi_QUERYARGUMENTS"]
        assert sqli.scope_down_statement is True
        assert web_acl.rules[1].overridden_to_count is False
        known_bad_inputs = web_acl.rules[2].managed_rule_group
        assert known_bad_inputs.name == "AWSManagedRulesKnownBadInputsRuleSet"
        assert known_bad_inputs.rule_action_overrides == {}
        assert known_bad_inputs.excluded_rules == []
        assert known_bad_inputs.scope_down_statement is False
        assert web_acl.rules[2].overridden_to_count is True

    @mock_aws
    def test_get_web_acl_firewall_manager_rule_groups(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            VisibilityConfig=WEB_ACL_VISIBILITY_CONFIG,
        )["Summary"]
        waf_arn = waf["ARN"]

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetWebACL":
                return {
                    "WebACL": {
                        "Name": waf["Name"],
                        "Id": waf["Id"],
                        "ARN": waf_arn,
                        "Rules": [],
                        "PreProcessFirewallManagerRuleGroups": [
                            {
                                "Name": "fms-sqli",
                                "Priority": 0,
                                "FirewallManagerStatement": {
                                    "ManagedRuleGroupStatement": {
                                        "VendorName": "AWS",
                                        "Name": "AWSManagedRulesSQLiRuleSet",
                                        "Version": "Version_2.0",
                                    }
                                },
                                "OverrideAction": {"None": {}},
                                "VisibilityConfig": {
                                    "SampledRequestsEnabled": True,
                                    "CloudWatchMetricsEnabled": True,
                                    "MetricName": "fms-sqli",
                                },
                            }
                        ],
                        "PostProcessFirewallManagerRuleGroups": [
                            {
                                "Name": "fms-custom-rule-group",
                                "Priority": 1,
                                "FirewallManagerStatement": {
                                    "RuleGroupReferenceStatement": {
                                        "ARN": f"arn:aws:wafv2:{AWS_REGION_EU_WEST_1}:123456789012:regional/rulegroup/custom/abc"
                                    }
                                },
                                "OverrideAction": {"Count": {}},
                                "VisibilityConfig": {
                                    "SampledRequestsEnabled": True,
                                    "CloudWatchMetricsEnabled": False,
                                    "MetricName": "fms-custom-rule-group",
                                },
                            }
                        ],
                    },
                    "LockToken": "token",
                }
            return make_api_call(self, operation_name, kwarg)

        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            wafv2 = WAFv2(aws)

        web_acl = wafv2.web_acls[waf_arn]
        assert web_acl.rules_retrieved
        assert web_acl.rules == []
        assert len(web_acl.rule_groups) == 2
        assert web_acl.rule_groups[0].name == "fms-sqli"
        assert web_acl.rule_groups[0].cloudwatch_metrics_enabled
        assert web_acl.rule_groups[0].managed_rule_group.vendor_name == "AWS"
        assert (
            web_acl.rule_groups[0].managed_rule_group.name
            == "AWSManagedRulesSQLiRuleSet"
        )
        assert web_acl.rule_groups[0].managed_rule_group.version == "Version_2.0"
        assert web_acl.rule_groups[0].overridden_to_count is False
        assert web_acl.rule_groups[1].name == "fms-custom-rule-group"
        assert not web_acl.rule_groups[1].cloudwatch_metrics_enabled
        assert web_acl.rule_groups[1].managed_rule_group is None
        assert web_acl.rule_groups[1].overridden_to_count is True

    @mock_aws
    def test_get_web_acl_failure_leaves_rules_unretrieved(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
        waf = wafv2.create_web_acl(
            Scope="REGIONAL",
            Name="my-web-acl",
            DefaultAction={"Allow": {}},
            Rules=[
                _managed_rule_group_rule("AWSManagedRulesSQLiRuleSet", 0, "None"),
            ],
            VisibilityConfig=WEB_ACL_VISIBILITY_CONFIG,
        )["Summary"]
        waf_arn = waf["ARN"]

        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "GetWebACL":
                raise _client_error(operation_name)
            return make_api_call(self, operation_name, kwarg)

        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            wafv2 = WAFv2(aws)

        assert wafv2.web_acls_list_failed_scopes == set()
        web_acl = wafv2.web_acls[waf_arn]
        assert not web_acl.rules_retrieved
        assert web_acl.rules == []
        assert web_acl.rule_groups == []

    @mock_aws
    def test_list_web_acls_failure_records_failed_scopes(self):
        def mock_make_api_call(self, operation_name, kwarg):
            if operation_name == "ListWebACLs":
                raise _client_error(operation_name)
            return make_api_call(self, operation_name, kwarg)

        aws = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        with patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call):
            wafv2 = WAFv2(aws)

        assert wafv2.web_acls == {}
        assert wafv2.web_acls_list_failed_scopes == {
            f"CLOUDFRONT:{AWS_REGION_US_EAST_1}",
            f"REGIONAL:{AWS_REGION_EU_WEST_1}",
        }
