from unittest import mock
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "ListResourcesForWebACL":
        return {"ResourceArns": []}
    if operation_name == "GetWebACL":
        if kwarg["Name"] == "test-rules-on":
            return {
                "WebACL": {
                    "Id": "web-acl-test",
                    "ARN": f"arn:aws:wafv2:{AWS_REGION_US_EAST_1}:123456789012:regional/webacl/test-rules-on",
                    "Name": "test-rules-on",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                    "Rules": [
                        {
                            "Name": "rule-on",
                            "Priority": 1,
                            "Statement": {
                                "ByteMatchStatement": {
                                    "SearchString": "test",
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [
                                        {"Type": "NONE", "Priority": 0}
                                    ],
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
                    "Tags": [{"Key": "Name", "Value": "web-acl-test"}],
                }
            }
        elif kwarg["Name"] == "test-rules-off":
            return {
                "WebACL": {
                    "Id": "web-acl-test",
                    "ARN": f"arn:aws:wafv2:{AWS_REGION_US_EAST_1}:123456789012:regional/webacl/test-rules-off",
                    "Name": "test-rules-off",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                    "Rules": [
                        {
                            "Name": "rule-off",
                            "Priority": 1,
                            "Statement": {
                                "ByteMatchStatement": {
                                    "SearchString": "test",
                                    "FieldToMatch": {"UriPath": {}},
                                    "TextTransformations": [
                                        {"Type": "NONE", "Priority": 0}
                                    ],
                                    "PositionalConstraint": "CONTAINS",
                                }
                            },
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": False,
                                "MetricName": "web-acl-test-metric",
                            },
                        }
                    ],
                    "Tags": [{"Key": "Name", "Value": "web-acl-test"}],
                }
            }
        elif kwarg["Name"] == "test-pre-rg-on":
            return {
                "WebACL": {
                    "Id": "web-acl-test-2",
                    "Name": "test-pre-rg-on",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "Tags": [{"Key": "Name", "Value": "web-acl-test-2"}],
                    "PreProcessFirewallManagerRuleGroups": [
                        {
                            "Name": "pre-rg-on",
                            "RuleGroupName": "AWSManagedRulesAdminProtectionRuleSet",
                            "Action": "NONE",
                            "OverrideAction": "NONE",
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": True,
                                "MetricName": "web-acl-test-metric",
                            },
                        }
                    ],
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            }
        elif kwarg["Name"] == "test-pre-rg-off":
            return {
                "WebACL": {
                    "Id": "web-acl-test-2",
                    "Name": "test-pre-rg-off",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "Tags": [{"Key": "Name", "Value": "web-acl-test-2"}],
                    "PreProcessFirewallManagerRuleGroups": [
                        {
                            "Name": "pre-rg-off",
                            "RuleGroupName": "AWSManagedRulesAdminProtectionRuleSet",
                            "Action": "NONE",
                            "OverrideAction": "NONE",
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": False,
                                "MetricName": "web-acl-test-metric",
                            },
                        }
                    ],
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            }
        elif kwarg["Name"] == "test-post-rg-on":
            return {
                "WebACL": {
                    "Id": "web-acl-test-2",
                    "Name": "test-post-rg-on",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "Tags": [{"Key": "Name", "Value": "web-acl-test-2"}],
                    "PostProcessFirewallManagerRuleGroups": [
                        {
                            "Name": "post-rg-on",
                            "RuleGroupName": "AWSManagedRulesAdminProtectionRuleSet",
                            "Action": "NONE",
                            "OverrideAction": "NONE",
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": True,
                                "MetricName": "web-acl-test-metric",
                            },
                        }
                    ],
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            }
        elif kwarg["Name"] == "test-post-rg-off":
            return {
                "WebACL": {
                    "Id": "web-acl-test-2",
                    "Name": "test-post-rg-off",
                    "Scope": "REGIONAL",
                    "DefaultAction": {"Allow": {}},
                    "Tags": [{"Key": "Name", "Value": "web-acl-test-2"}],
                    "PostProcessFirewallManagerRuleGroups": [
                        {
                            "Name": "post-rg-off",
                            "RuleGroupName": "AWSManagedRulesAdminProtectionRuleSet",
                            "Action": "NONE",
                            "OverrideAction": "NONE",
                            "VisibilityConfig": {
                                "SampledRequestsEnabled": True,
                                "CloudWatchMetricsEnabled": False,
                                "MetricName": "web-acl-test-metric",
                            },
                        }
                    ],
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                }
            }

    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_wafv2_cloudwatch_metrics_enabled:
    @mock_aws
    def test_no_web_acls(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_web_acl_rules(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2_client.create_web_acl(
            Name="web-acl-test",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
        )
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_web_acl_metric_in_rules(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules-on",
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
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf["Id"]} does have CloudWatch Metrics enabled in all rule groups and rules."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_no_metric_in_rules(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules-off",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rule-off",
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
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            expected_status_extended = f"AWS WAFv2 Web ACL {waf["Id"]} does not have CloudWatch Metrics enabled in all rule groups and rules.\n\t\t\tNon compliant reources are:"
            expected_status_extended += "\n\t\t\t\t· Rules: rule-off."

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_web_acl_metric_in_pre_process_firewall_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-pre-rg-on",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf["Id"]} does have CloudWatch Metrics enabled in all rule groups and rules."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_no_metric_in_pre_process_firewall_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-pre-rg-off",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            expected_status_extended = f"AWS WAFv2 Web ACL {waf["Id"]} does not have CloudWatch Metrics enabled in all rule groups and rules.\n\t\t\tNon compliant reources are:"
            expected_status_extended += (
                "\n\t\t\t\t· Pre-Process Rule Groups: pre-rg-off."
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_web_acl_metric_in_post_process_firewall_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-post-rg-on",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf["Id"]} does have CloudWatch Metrics enabled in all rule groups and rules."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_no_metric_in_post_process_firewall_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-post-rg-off",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )
        waf = waf["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_cloudwatch_metrics_enabled.wafv2_cloudwatch_metrics_enabled import (
                wafv2_cloudwatch_metrics_enabled,
            )

            check = wafv2_cloudwatch_metrics_enabled()
            result = check.execute()

            expected_status_extended = f"AWS WAFv2 Web ACL {waf["Id"]} does not have CloudWatch Metrics enabled in all rule groups and rules.\n\t\t\tNon compliant reources are:"
            expected_status_extended += (
                "\n\t\t\t\t· Post-Process Rule Groups: post-rg-off."
            )

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == expected_status_extended
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]
