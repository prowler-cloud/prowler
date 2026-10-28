from unittest import mock

from prowler.providers.aws.services.wafv2.wafv2_service import (
    ManagedRuleGroup,
    Rule,
    WebAclv2,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_managed_rule_groups_enabled.wafv2_webacl_managed_rule_groups_enabled"
WEB_ACL_ARN = f"arn:aws:wafv2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:regional/webacl/test-acl/abc"


def _web_acl(rules):
    return WebAclv2(
        arn=WEB_ACL_ARN,
        name="test-acl",
        id="abc",
        albs=[],
        user_pools=[],
        region=AWS_REGION_US_EAST_1,
        tags=[],
        rules=rules,
    )


def _run_check(web_acls):
    wafv2_client = mock.MagicMock()
    wafv2_client.web_acls = web_acls

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ),
        mock.patch(f"{CHECK_PATH}.wafv2_client", new=wafv2_client),
    ):
        from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_rule_groups_enabled.wafv2_webacl_managed_rule_groups_enabled import (
            wafv2_webacl_managed_rule_groups_enabled,
        )

        return wafv2_webacl_managed_rule_groups_enabled().execute()


class Test_wafv2_webacl_managed_rule_groups_enabled:
    def test_no_web_acls(self):
        assert len(_run_check({})) == 0

    def test_no_managed_rule_groups(self):
        result = _run_check({WEB_ACL_ARN: _web_acl([Rule(name="custom-rule")])})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL test-acl does not use any managed rule group."
        )
        assert result[0].resource_id == "abc"
        assert result[0].resource_arn == WEB_ACL_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_managed_rule_groups(self):
        rules = [
            Rule(name="custom-rule"),
            Rule(
                name="AWS-AWSManagedRulesCommonRuleSet",
                managed_rule_group=ManagedRuleGroup(
                    vendor_name="AWS", name="AWSManagedRulesCommonRuleSet"
                ),
            ),
            Rule(
                name="AWS-AWSManagedRulesPHPRuleSet",
                managed_rule_group=ManagedRuleGroup(
                    vendor_name="AWS",
                    name="AWSManagedRulesPHPRuleSet",
                    version="Version_2.3",
                ),
            ),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules)})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == "AWS WAFv2 Web ACL test-acl uses managed rule groups: AWS/AWSManagedRulesCommonRuleSet, AWS/AWSManagedRulesPHPRuleSet."
        )
