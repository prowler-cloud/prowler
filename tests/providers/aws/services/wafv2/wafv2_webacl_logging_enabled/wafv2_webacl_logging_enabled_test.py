from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_wafv2_webacl_rule_logging_enabled:
    @mock_aws
    def test_no_web_acls(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_wafv2_web_acl_with_logging_in_rules(self):
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

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does have CloudWatch Metrics enabled in all its rules."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_without_logging_in_rules(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules",
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
                        "CloudWatchMetricsEnabled": False,
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

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does not have CloudWatch Metrics enabled in rules: rule-off."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_with_logging_in_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules",
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
            Tags=[{"Key": "Name", "Value": "test-rules"}],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]
        waf_arn = waf["ARN"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does have CloudWatch Metrics enabled in all its rules."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_without_logging_in_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "rg-off",
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
                        "CloudWatchMetricsEnabled": False,
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

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does not have CloudWatch Metrics enabled in rule groups: rg-off."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_with_logging_in_both(self):
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
                },
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
                },
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

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does have CloudWatch Metrics enabled in all its rules."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]

    @mock_aws
    def test_wafv2_web_acl_without_logging_in_both(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rules",
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
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                },
                {
                    "Name": "rg-off",
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
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "web-acl-test-metric",
                    },
                },
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

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does not have CloudWatch Metrics enabled in rules: rule-off nor in rule groups: rg-off."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": waf_name}]
