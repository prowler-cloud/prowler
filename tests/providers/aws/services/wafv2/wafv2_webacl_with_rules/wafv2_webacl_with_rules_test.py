from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call

FM_RG_NAME = "test-firewall-managed-rule-group"
FM_RG_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/test-firewall-managed-rule-group"


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {
                    "Name": FM_RG_NAME,
                    "Id": FM_RG_NAME,
                    "ARN": FM_RG_ARN,
                }
            ]
        }
    elif operation_name == "GetWebACL":
        return {
            "WebACL": {
                "PostProcessFirewallManagerRuleGroups": [
                    {
                        "Name": FM_RG_NAME,
                        "VisibilityConfig": {
                            "SampledRequestsEnabled": True,
                            "CloudWatchMetricsEnabled": True,
                            "MetricName": "web-acl-test-metric",
                        },
                    }
                ]
            }
        }
    elif operation_name == "ListResourcesForWebACL":
        return {
            "ResourceArns": [
                FM_RG_ARN,
            ]
        }
    elif operation_name == "ListTagsForResource":
        return {
            "TagInfoForResource": {
                "ResourceARN": FM_RG_ARN,
                "TagList": [{"Key": "Name", "Value": FM_RG_NAME}],
            }
        }
    return orig(self, operation_name, kwarg)


class Test_wafv2_webacl_with_rules:
    @mock_aws
    def test_no_web_acls(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules.wafv2_client",
                new=WAFv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules import (
                wafv2_webacl_with_rules,
            )

            check = wafv2_webacl_with_rules()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_wafv2_web_acl_with_rule(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules",
            Scope="REGIONAL",
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
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "test-rules"}],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]
        waf_arn = waf["ARN"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules.wafv2_client",
                new=WAFv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules import (
                wafv2_webacl_with_rules,
            )

            check = wafv2_webacl_with_rules()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does have rules or rule groups attached."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_with_rule_group(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rule-groups",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rg-on",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        },
                        "RuleGroupReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/ManagedRuleGroup/af9d9b6b-1d1b-4e0d-8f3e-1d1d0e1d0e1d",
                        },
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            ],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "test-rule-groups"}],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]
        waf_arn = waf["ARN"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules.wafv2_client",
                new=WAFv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules import (
                wafv2_webacl_with_rules,
            )

            check = wafv2_webacl_with_rules()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does have rules or rule groups attached."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call,
    )
    @mock_aws
    def test_wafv2_web_acl_with_firewall_manager_managed_rule_group(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules.wafv2_client",
                new=WAFv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules import (
                wafv2_webacl_with_rules,
            )

            check = wafv2_webacl_with_rules()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {FM_RG_NAME} does have rules or rule groups attached."
            )
            assert result[0].resource_id == FM_RG_NAME
            assert result[0].resource_arn == FM_RG_ARN
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": FM_RG_NAME}]

    @mock_aws
    def test_wafv2_web_acl_without_rule_or_rule_group(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-none",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[],
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "test-none"}],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]
        waf_arn = waf["ARN"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules.wafv2_client",
                new=WAFv2(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_with_rules.wafv2_webacl_with_rules import (
                wafv2_webacl_with_rules,
            )

            check = wafv2_webacl_with_rules()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does not have any rules or rule groups attached."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]
