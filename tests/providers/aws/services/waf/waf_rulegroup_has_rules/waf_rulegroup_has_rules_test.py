from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

RULE_GROUP_ID = "test-rulegroup-id"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call_compliant_rule_group(self, operation_name, kwarg):
    unused_operations = ["ListRules", "GetRule", "ListWebACLs", "GetRule"]
    if operation_name in unused_operations:
        return {}
    if operation_name == "ListRuleGroups":
        return {
            "RuleGroups": [
                {
                    "RuleGroupId": RULE_GROUP_ID,
                    "Name": RULE_GROUP_ID,
                },
            ]
        }
    if operation_name == "ListActivatedRulesInRuleGroup":
        return {
            "ActivatedRules": [
                {
                    "RuleId": RULE_GROUP_ID,
                },
            ]
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_non_compliant_rule_group(self, operation_name, kwarg):
    unused_operations = ["ListRules", "GetRule", "ListWebACLs", "GetRule"]
    if operation_name in unused_operations:
        return {}
    if operation_name == "ListRuleGroups":
        return {
            "RuleGroups": [
                {
                    "RuleGroupId": RULE_GROUP_ID,
                    "Name": RULE_GROUP_ID,
                },
            ]
        }
    if operation_name == "ListActivatedRulesInRuleGroup":
        return {"Rules": []}
    return orig(self, operation_name, kwarg)


class Test_waf_rulegroup_has_rules:
    @mock_aws
    def test_no_rule_groups(self):
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules import (
                    waf_rulegroup_has_rules,
                )

                check = waf_rulegroup_has_rules()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_compliant_rule_group,
    )
    @mock_aws
    def test_waf_rules_with_condition(self):
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules import (
                    waf_rulegroup_has_rules,
                )

                check = waf_rulegroup_has_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Regional Classic Regional RuleGroup {RULE_GROUP_ID} has at least one rule."
                )
                assert result[0].resource_id == RULE_GROUP_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/{RULE_GROUP_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_non_compliant_rule_group,
    )
    @mock_aws
    def test_waf_rules_without_condition(self):
        from prowler.providers.aws.services.waf.waf_service import WAFRegional

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules.wafregional_client",
                new=WAFRegional(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_rulegroup_has_rules.waf_rulegroup_has_rules import (
                    waf_rulegroup_has_rules,
                )

                check = waf_rulegroup_has_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Regional Classic Regional RuleGroup {RULE_GROUP_ID} does not have any rules."
                )
                assert result[0].resource_id == RULE_GROUP_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf-regional:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rulegroup/{RULE_GROUP_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
