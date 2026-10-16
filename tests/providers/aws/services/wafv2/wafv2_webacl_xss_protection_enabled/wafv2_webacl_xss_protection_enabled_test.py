from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_xss_protection_enabled.wafv2_webacl_xss_protection_enabled"

VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "metric",
}


def _common_rule_set_rule(priority=1, override_to_count=False):
    return {
        "Name": "AWS-CommonRuleSet",
        "Priority": priority,
        "Statement": {
            "ManagedRuleGroupStatement": {
                "VendorName": "AWS",
                "Name": "AWSManagedRulesCommonRuleSet",
            }
        },
        "OverrideAction": {"Count": {}} if override_to_count else {"None": {}},
        "VisibilityConfig": {**VISIBILITY, "MetricName": "AWS-CommonRuleSet"},
    }


def _xss_rule(name="xss", priority=1, action=None, nested=False):
    xss_statement = {
        "XssMatchStatement": {
            "FieldToMatch": {"Body": {}},
            "TextTransformations": [{"Type": "URL_DECODE", "Priority": 0}],
        }
    }
    if nested:
        statement = {
            "AndStatement": {
                "Statements": [
                    {
                        "ByteMatchStatement": {
                            "SearchString": "x",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    xss_statement,
                ]
            }
        }
    else:
        statement = xss_statement
    return {
        "Name": name,
        "Priority": priority,
        "Statement": statement,
        "Action": action or {"Block": {}},
        "VisibilityConfig": {**VISIBILITY, "MetricName": name},
    }


def _run_check(aws_provider):
    from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
    ):
        from prowler.providers.aws.services.wafv2.wafv2_webacl_xss_protection_enabled.wafv2_webacl_xss_protection_enabled import (
            wafv2_webacl_xss_protection_enabled,
        )

        return wafv2_webacl_xss_protection_enabled().execute()


class Test_wafv2_webacl_xss_protection_enabled:
    @mock_aws
    def test_no_web_acls(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)
        assert len(result) == 0

    @mock_aws
    def test_common_rule_set_enabled(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2.create_web_acl(
            Name="waf-crs",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_common_rule_set_rule()],
            VisibilityConfig=VISIBILITY,
        )["Summary"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL waf-crs has XSS protection enabled through the "
            "AWSManagedRulesCommonRuleSet managed rule group."
        )
        assert result[0].resource_id == waf["Id"]
        assert result[0].resource_arn == waf["ARN"]
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_custom_xss_match_statement(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-custom-xss",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_xss_rule()],
            VisibilityConfig=VISIBILITY,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL waf-custom-xss has XSS protection enabled through "
            "custom XssMatchStatement rules."
        )

    @mock_aws
    def test_custom_xss_match_statement_nested(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-nested-xss",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_xss_rule(name="nested", nested=True)],
            VisibilityConfig=VISIBILITY,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_custom_xss_match_statement_count_action_not_protective(self):
        # An XssMatchStatement with a Count action does not block malicious requests, so it
        # is not counted as active protection.
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-xss-count",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_xss_rule(name="xss-count", action={"Count": {}})],
            VisibilityConfig=VISIBILITY,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL waf-xss-count does not have XSS protection enabled."
        )

    @mock_aws
    def test_common_rule_set_overridden_to_count(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-crs-count",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_common_rule_set_rule(override_to_count=True)],
            VisibilityConfig=VISIBILITY,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_no_xss_protection(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-no-xss",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "sqli",
                    "Priority": 1,
                    "Statement": {
                        "ManagedRuleGroupStatement": {
                            "VendorName": "AWS",
                            "Name": "AWSManagedRulesSQLiRuleSet",
                        }
                    },
                    "OverrideAction": {"None": {}},
                    "VisibilityConfig": {**VISIBILITY, "MetricName": "sqli"},
                }
            ],
            VisibilityConfig=VISIBILITY,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        result = _run_check(aws_provider)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL waf-no-xss does not have XSS protection enabled."
        )
