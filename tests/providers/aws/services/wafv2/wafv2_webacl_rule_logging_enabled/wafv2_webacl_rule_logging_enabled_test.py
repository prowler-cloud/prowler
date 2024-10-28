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
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_no_web_acl_rules_or_rule_groups(self):
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
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 0

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
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
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
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

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
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
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
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @mock_aws
    def test_web_acl_metric_in_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rg-off",
            Scope="CLOUDFRONT",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
            Rules=[
                {
                    "Name": "rule-group-off",
                    "Priority": 1,
                    "Statement": {
                        "RuleGroupReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/test-rule-group/1a2b3c4d-5678-90ab-cdef-EXAMPLE11111"
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": True,
                        "MetricName": "rule-group-off-metric",
                    },
                }
            ],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
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
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]

    @mock_aws
    def test_no_metric_in_rule_groups(self):
        wafv2_client = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2_client.create_web_acl(
            Name="test-rg-off",
            Scope="CLOUDFRONT",
            DefaultAction={"Allow": {}},
            VisibilityConfig={
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": False,
                "MetricName": "web-acl-test-metric",
            },
            Tags=[{"Key": "Name", "Value": "web-acl-test"}],
            Rules=[
                {
                    "Name": "rule-group-off",
                    "Priority": 1,
                    "Statement": {
                        "RuleGroupReferenceStatement": {
                            "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/test-rule-group/1a2b3c4d-5678-90ab-cdef-EXAMPLE11111"
                        }
                    },
                    "VisibilityConfig": {
                        "SampledRequestsEnabled": True,
                        "CloudWatchMetricsEnabled": False,
                        "MetricName": "rule-group-off-metric",
                    },
                }
            ],
        )["Summary"]
        waf_id = waf["Id"]
        waf_name = waf["Name"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled.wafv2_client",
            new=WAFv2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.wafv2.wafv2_webacl_rule_logging_enabled.wafv2_webacl_rule_logging_enabled import (
                wafv2_webacl_rule_logging_enabled,
            )

            check = wafv2_webacl_rule_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"AWS WAFv2 Web ACL {waf_name} does not have CloudWatch Metrics enabled in rule groups: rule-group-off."
            )
            assert result[0].resource_id == waf_id
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "web-acl-test"}]
