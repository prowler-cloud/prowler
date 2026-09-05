from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled"

VISIBILITY = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "metric",
}


def _managed_rule(name, priority, override_to_count=False, rule_action_overrides=None):
    managed_statement = {"VendorName": "AWS", "Name": name}
    if rule_action_overrides:
        managed_statement["RuleActionOverrides"] = rule_action_overrides
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": managed_statement},
        "OverrideAction": {"Count": {}} if override_to_count else {"None": {}},
        "VisibilityConfig": {**VISIBILITY, "MetricName": name},
    }


class Test_wafv2_webacl_managed_injection_rule_groups_enabled:
    @mock_aws
    def test_no_web_acls(self):
        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_both_managed_groups_enabled(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        waf = wafv2.create_web_acl(
            Name="waf-both",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                _managed_rule("AWSManagedRulesSQLiRuleSet", 1),
                _managed_rule("AWSManagedRulesKnownBadInputsRuleSet", 2),
            ],
            VisibilityConfig=VISIBILITY,
            Tags=[{"Key": "Name", "Value": "waf-both"}],
        )["Summary"]

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "AWS WAFv2 Web ACL waf-both has the AWS managed injection rule groups "
                "AWSManagedRulesSQLiRuleSet and AWSManagedRulesKnownBadInputsRuleSet enabled."
            )
            assert result[0].resource_id == waf["Id"]
            assert result[0].resource_arn == waf["ARN"]
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_managed_group_missing(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-missing",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[_managed_rule("AWSManagedRulesSQLiRuleSet", 1)],
            VisibilityConfig=VISIBILITY,
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "AWS WAFv2 Web ACL waf-missing does not have the following AWS managed "
                "injection rule groups enabled: AWSManagedRulesKnownBadInputsRuleSet."
            )

    @mock_aws
    def test_managed_group_overridden_to_count(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-count",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                _managed_rule("AWSManagedRulesSQLiRuleSet", 1),
                # KnownBadInputs present but whole group overridden to Count -> excluded.
                _managed_rule(
                    "AWSManagedRulesKnownBadInputsRuleSet", 2, override_to_count=True
                ),
            ],
            VisibilityConfig=VISIBILITY,
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                "AWSManagedRulesKnownBadInputsRuleSet"
                in result[0].status_extended
            )

    @mock_aws
    def test_managed_groups_nested_in_and_statement(self):
        # Managed rule groups can only appear as top-level rule statements, but the recursive
        # parser must still find both groups referenced across separate rules.
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-nested",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                _managed_rule(
                    "AWSManagedRulesKnownBadInputsRuleSet",
                    1,
                    rule_action_overrides=[
                        {"Name": "Host_localhost_HEADER", "ActionToUse": {"Count": {}}}
                    ],
                ),
                _managed_rule("AWSManagedRulesSQLiRuleSet", 2),
            ],
            VisibilityConfig=VISIBILITY,
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            # Both groups present and not overridden wholesale -> PASS even though one
            # individual rule inside a group is set to Count.
            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_no_managed_groups(self):
        wafv2 = client("wafv2", region_name=AWS_REGION_US_EAST_1)
        wafv2.create_web_acl(
            Name="waf-none",
            Scope="REGIONAL",
            DefaultAction={"Allow": {}},
            Rules=[
                {
                    "Name": "byte-match",
                    "Priority": 1,
                    "Statement": {
                        "ByteMatchStatement": {
                            "SearchString": "test",
                            "FieldToMatch": {"UriPath": {}},
                            "TextTransformations": [{"Type": "NONE", "Priority": 0}],
                            "PositionalConstraint": "CONTAINS",
                        }
                    },
                    "Action": {"Block": {}},
                    "VisibilityConfig": VISIBILITY,
                }
            ],
            VisibilityConfig=VISIBILITY,
        )

        from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_PATH}.wafv2_client", new=WAFv2(aws_provider)),
        ):
            from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
                wafv2_webacl_managed_injection_rule_groups_enabled,
            )

            check = wafv2_webacl_managed_injection_rule_groups_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
