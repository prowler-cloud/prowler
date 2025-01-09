from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

RULE_ID = "test-rule-id"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call_compliant_rule(self, operation_name, kwarg):
    if operation_name == "ListRules":
        return {
            "Rules": [
                {
                    "RuleId": RULE_ID,
                    "Name": RULE_ID,
                },
            ]
        }
    if operation_name == "GetRule":
        return {
            "Rule": {
                "RuleId": RULE_ID,
                "Predicates": [
                    {
                        "Negated": False,
                        "Type": "IPMatch",
                        "DataId": "IPSetId",
                    },
                ],
            }
        }
    return orig(self, operation_name, kwarg)


def mock_make_api_call_non_compliant_rule(self, operation_name, kwarg):
    if operation_name == "ListRules":
        return {
            "Rules": [
                {
                    "RuleId": RULE_ID,
                    "Name": RULE_ID,
                },
            ]
        }
    if operation_name == "GetRule":
        return {
            "Rule": {
                "RuleId": RULE_ID,
                "Predicates": [],
            }
        }
    return orig(self, operation_name, kwarg)


class Test_waf_global_rule_with_conditions:
    @mock_aws
    def test_no_rules(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions import (
                    waf_global_rule_with_conditions,
                )

                check = waf_global_rule_with_conditions()
                result = check.execute()

                assert len(result) == 0

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_compliant_rule,
    )
    @mock_aws
    def test_waf_rules_with_condition(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions import (
                    waf_global_rule_with_conditions,
                )

                check = waf_global_rule_with_conditions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Rule {RULE_ID} has at least one condition."
                )
                assert result[0].resource_id == RULE_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/{RULE_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_non_compliant_rule,
    )
    @mock_aws
    def test_waf_rules_without_condition(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_rule_with_conditions.waf_global_rule_with_conditions import (
                    waf_global_rule_with_conditions,
                )

                check = waf_global_rule_with_conditions()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Rule {RULE_ID} does not have any conditions."
                )
                assert result[0].resource_id == RULE_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:rule/{RULE_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
