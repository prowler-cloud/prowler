from unittest import mock
from unittest.mock import patch

import botocore
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

WEB_ACL_ID = "test-web-acl-id"
WEB_ACL_NAME = "test-web-acl-name"

# Original botocore _make_api_call function
orig = botocore.client.BaseClient._make_api_call


# Mocked botocore _make_api_call function
def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [],
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_only_rules(self, operation_name, kwarg):
    unused_operations = [
        "ListResourcesForWebACL",
        "ListRuleGroups",
        "ListActivatedRulesInRuleGroup",
    ]
    if operation_name in unused_operations:
        return {}
    if operation_name == "ListRules":
        return {
            "Rules": [
                {
                    "RuleId": "my-rule-id",
                    "Name": "my-rule",
                },
            ]
        }
    if operation_name == "GetRule":
        return {
            "Rule": {
                "RuleId": "my-rule-id",
                "Name": "my-rule",
                "Predicates": [
                    {
                        "Negated": False,
                        "Type": "IPMatch",
                        "DataId": "my-data-id",
                    }
                ],
            }
        }
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [
                    {
                        "RuleId": "my-rule-id",
                        "Type": "BLOCK",
                    }
                ],
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_only_rule_groups(self, operation_name, kwarg):
    unused_operations = [
        "ListResourcesForWebACL",
        "ListRules",
        "GetRule",
    ]
    if operation_name in unused_operations:
        return {}
    if operation_name == "ListRuleGroups":
        return {
            "RuleGroups": [
                {
                    "RuleGroupId": "my-rule-group-id",
                    "Name": "my-rule-group",
                },
            ]
        }
    if operation_name == "ListActivatedRulesInRuleGroup":
        return {}
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [
                    {
                        "RuleId": "my-rule-group-id",
                        "Type": "GROUP",
                    }
                ],
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


def mock_make_api_call_both(self, operation_name, kwarg):
    unused_operations = [
        "ListResourcesForWebACL",
    ]
    if operation_name in unused_operations:
        return {}
    if operation_name == "ListRules":
        return {
            "Rules": [
                {
                    "RuleId": "my-rule-id",
                    "Name": "my-rule",
                },
            ]
        }
    if operation_name == "GetRule":
        return {
            "Rule": {
                "RuleId": "my-rule-id",
                "Name": "my-rule",
                "Predicates": [
                    {
                        "Negated": False,
                        "Type": "IPMatch",
                        "DataId": "my-data-id",
                    }
                ],
            }
        }
    if operation_name == "ListRuleGroups":
        return {
            "RuleGroups": [
                {
                    "RuleGroupId": "my-rule-group-id",
                    "Name": "my-rule-group",
                },
            ]
        }
    if operation_name == "ListActivatedRulesInRuleGroup":
        return {
            "ActivatedRules": [
                {
                    "RuleId": "my-rule-id",
                },
            ]
        }
    if operation_name == "GetChangeToken":
        return {"ChangeToken": "my-change-token"}
    if operation_name == "ListWebACLs":
        return {
            "WebACLs": [
                {"WebACLId": WEB_ACL_ID, "Name": WEB_ACL_NAME},
            ]
        }
    if operation_name == "GetWebACL":
        return {
            "WebACL": {
                "Rules": [
                    {
                        "RuleId": "my-rule-id",
                        "Type": "BLOCK",
                    },
                    {
                        "RuleId": "my-rule-group-id",
                        "Type": "GROUP",
                    },
                ],
            }
        }
    # If we don't want to patch the API call
    return orig(self, operation_name, kwarg)


class Test_waf_global_webacl_with_rules:
    @mock_aws
    def test_no_waf(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules import (
                    waf_global_webacl_with_rules,
                )

                check = waf_global_webacl_with_rules()
                result = check.execute()

                assert len(result) == 0

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    @mock_aws
    def test_waf_no_rules_and_no_rule_group(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules import (
                    waf_global_webacl_with_rules,
                )

                check = waf_global_webacl_with_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} does not have any rules or rule groups."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_only_rules
    )
    @mock_aws
    def test_waf_rules_and_no_rule_group(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules import (
                    waf_global_webacl_with_rules,
                )

                check = waf_global_webacl_with_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} has at least one rule or rule group."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_only_rule_groups,
    )
    @mock_aws
    def test_waf_no_rules_and_rule_group(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules import (
                    waf_global_webacl_with_rules,
                )

                check = waf_global_webacl_with_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} has at least one rule or rule group."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call_both)
    @mock_aws
    def test_waf_rules_and_rule_group(self):
        from prowler.providers.aws.services.waf.waf_service import WAF

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules.waf_client",
                new=WAF(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.waf.waf_global_webacl_with_rules.waf_global_webacl_with_rules import (
                    waf_global_webacl_with_rules,
                )

                check = waf_global_webacl_with_rules()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"AWS WAF Global Web ACL {WEB_ACL_NAME} has at least one rule or rule group."
                )
                assert result[0].resource_id == WEB_ACL_ID
                assert (
                    result[0].resource_arn
                    == f"arn:aws:waf:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:webacl/{WEB_ACL_ID}"
                )
                assert result[0].region == AWS_REGION_US_EAST_1
