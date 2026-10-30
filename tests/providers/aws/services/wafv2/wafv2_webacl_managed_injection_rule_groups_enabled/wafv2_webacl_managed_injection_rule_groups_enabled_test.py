from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.wafv2.wafv2_service import (
    ManagedRuleGroup,
    Rule,
    Scope,
    WebAclv2,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_PATH = "prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled"
WEB_ACL_NAME = "test-acl"
WEB_ACL_ID = "abc"
WEB_ACL_ARN = f"arn:aws:wafv2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:regional/webacl/{WEB_ACL_NAME}/{WEB_ACL_ID}"
CLOUDFRONT_WEB_ACL_ARN = f"arn:aws:wafv2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:global/webacl/{WEB_ACL_NAME}/{WEB_ACL_ID}"

PASS_MESSAGE = f"AWS WAFv2 Web ACL {WEB_ACL_NAME} enforces the AWS managed injection rule groups AWSManagedRulesSQLiRuleSet and AWSManagedRulesKnownBadInputsRuleSet."
BOTH_MISSING_MESSAGE = f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesSQLiRuleSet is missing, AWSManagedRulesKnownBadInputsRuleSet is missing."
VISIBILITY_CONFIG = {
    "SampledRequestsEnabled": True,
    "CloudWatchMetricsEnabled": True,
    "MetricName": "metric",
}


def _managed_rule(name, vendor_name="AWS", overridden_to_count=False):
    return Rule(
        name=f"{vendor_name}-{name}",
        cloudwatch_metrics_enabled=True,
        managed_rule_group=ManagedRuleGroup(vendor_name=vendor_name, name=name),
        overridden_to_count=overridden_to_count,
    )


def _sqli_rule(**kwargs):
    return _managed_rule("AWSManagedRulesSQLiRuleSet", **kwargs)


def _known_bad_inputs_rule(**kwargs):
    return _managed_rule("AWSManagedRulesKnownBadInputsRuleSet", **kwargs)


def _web_acl(
    rules=None,
    rule_groups=None,
    rules_retrieved=True,
    scope=Scope.REGIONAL,
    region=AWS_REGION_EU_WEST_1,
    arn=WEB_ACL_ARN,
    name=WEB_ACL_NAME,
):
    return WebAclv2(
        arn=arn,
        name=name,
        id=WEB_ACL_ID,
        albs=[],
        user_pools=[],
        region=region,
        tags=[],
        scope=scope,
        rules=rules or [],
        rule_groups=rule_groups or [],
        rules_retrieved=rules_retrieved,
    )


def _api_managed_rule(name, priority, override_action):
    """Raw GetWebACL/CreateWebACL rule referencing an AWS managed rule group."""
    return {
        "Name": f"AWS-{name}",
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": "AWS", "Name": name}},
        "OverrideAction": {override_action: {}},
        "VisibilityConfig": {**VISIBILITY_CONFIG, "MetricName": name},
    }


def _execute_check(wafv2_client, regions):
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(regions),
        ),
        mock.patch(f"{CHECK_PATH}.wafv2_client", new=wafv2_client),
    ):
        from prowler.providers.aws.services.wafv2.wafv2_webacl_managed_injection_rule_groups_enabled.wafv2_webacl_managed_injection_rule_groups_enabled import (
            wafv2_webacl_managed_injection_rule_groups_enabled,
        )

        return wafv2_webacl_managed_injection_rule_groups_enabled().execute()


def _run_check(web_acls, failed_scopes=None):
    wafv2_client = mock.MagicMock()
    wafv2_client.web_acls = web_acls
    wafv2_client.web_acls_list_failed_scopes = failed_scopes or set()
    wafv2_client.region = AWS_REGION_US_EAST_1
    wafv2_client.audited_account = AWS_ACCOUNT_NUMBER
    wafv2_client.audited_account_arn = AWS_ACCOUNT_ARN
    return _execute_check(wafv2_client, [AWS_REGION_US_EAST_1, AWS_REGION_EU_WEST_1])


def _run_check_with_moto(rules):
    """Create a Web ACL in moto and run the check through the real WAFv2 service."""
    wafv2 = client("wafv2", region_name=AWS_REGION_EU_WEST_1)
    web_acl = wafv2.create_web_acl(
        Scope="REGIONAL",
        Name=WEB_ACL_NAME,
        DefaultAction={"Allow": {}},
        Rules=rules,
        VisibilityConfig=VISIBILITY_CONFIG,
    )["Summary"]

    from prowler.providers.aws.services.wafv2.wafv2_service import WAFv2

    aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
    return web_acl, _execute_check(WAFv2(aws_provider), [AWS_REGION_EU_WEST_1])


class Test_wafv2_webacl_managed_injection_rule_groups_enabled:
    def test_no_web_acls(self):
        assert len(_run_check({})) == 0

    def test_both_rule_groups_enforced(self):
        rules = [
            Rule(name="custom-rule"),
            _sqli_rule(),
            _known_bad_inputs_rule(),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == PASS_MESSAGE
        assert result[0].resource_id == WEB_ACL_ID
        assert result[0].resource_arn == WEB_ACL_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1
        assert result[0].resource_tags == []

    def test_rule_groups_enforced_through_firewall_manager(self):
        web_acl = _web_acl(
            rules=[_sqli_rule()],
            rule_groups=[Rule(name="custom-rule-group"), _known_bad_inputs_rule()],
        )
        result = _run_check({WEB_ACL_ARN: web_acl})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == PASS_MESSAGE

    def test_counted_and_enforced_reference_of_the_same_rule_group(self):
        rules = [
            _sqli_rule(overridden_to_count=True),
            _sqli_rule(),
            _known_bad_inputs_rule(),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == PASS_MESSAGE

    def test_no_rules(self):
        result = _run_check({WEB_ACL_ARN: _web_acl()})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == BOTH_MISSING_MESSAGE
        assert result[0].resource_id == WEB_ACL_ID
        assert result[0].resource_arn == WEB_ACL_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1

    def test_only_unrelated_managed_rule_groups(self):
        rules = [
            _managed_rule("AWSManagedRulesCommonRuleSet"),
            _managed_rule("AWSManagedRulesPHPRuleSet"),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == BOTH_MISSING_MESSAGE

    def test_known_bad_inputs_rule_group_missing(self):
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=[_sqli_rule()])})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesKnownBadInputsRuleSet is missing."
        )

    def test_sqli_rule_group_missing(self):
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=[_known_bad_inputs_rule()])})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesSQLiRuleSet is missing."
        )

    def test_rule_group_overridden_to_count(self):
        rules = [_sqli_rule(), _known_bad_inputs_rule(overridden_to_count=True)]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesKnownBadInputsRuleSet is overridden to Count."
        )

    def test_both_rule_groups_overridden_to_count(self):
        rules = [
            _sqli_rule(overridden_to_count=True),
            _known_bad_inputs_rule(overridden_to_count=True),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesSQLiRuleSet is overridden to Count, AWSManagedRulesKnownBadInputsRuleSet is overridden to Count."
        )

    def test_firewall_manager_rule_group_overridden_to_count(self):
        web_acl = _web_acl(
            rules=[_known_bad_inputs_rule()],
            rule_groups=[_sqli_rule(overridden_to_count=True)],
        )
        result = _run_check({WEB_ACL_ARN: web_acl})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesSQLiRuleSet is overridden to Count."
        )

    def test_rule_groups_from_other_vendor_are_not_enforced(self):
        rules = [
            _sqli_rule(vendor_name="ThirdPartyVendor"),
            _known_bad_inputs_rule(vendor_name="ThirdPartyVendor"),
        ]
        result = _run_check({WEB_ACL_ARN: _web_acl(rules=rules)})
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == BOTH_MISSING_MESSAGE

    def test_rules_not_retrieved_regional(self):
        result = _run_check({WEB_ACL_ARN: _web_acl(rules_retrieved=False)})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Cannot evaluate AWS WAFv2 managed injection rule groups: rules could not be retrieved for Web ACLs {WEB_ACL_NAME} (REGIONAL:{AWS_REGION_EU_WEST_1}), verify that wafv2:GetWebACL is granted to the scanning identity."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_arn == AWS_ACCOUNT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_rules_not_retrieved_cloudfront(self):
        web_acl = _web_acl(
            rules_retrieved=False,
            scope=Scope.CLOUDFRONT,
            region=AWS_REGION_US_EAST_1,
            arn=CLOUDFRONT_WEB_ACL_ARN,
        )
        result = _run_check({CLOUDFRONT_WEB_ACL_ARN: web_acl})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == f"Cannot evaluate AWS WAFv2 managed injection rule groups: rules could not be retrieved for Web ACLs {WEB_ACL_NAME} (CLOUDFRONT:{AWS_REGION_US_EAST_1}), verify that wafv2:GetWebACL is granted to the scanning identity and that us-east-1 is included in the scan for CLOUDFRONT Web ACLs."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_arn == AWS_ACCOUNT_ARN

    def test_rules_not_retrieved_with_partial_rules(self):
        """A partially read Web ACL is MANUAL even if the rules read so far would pass."""
        web_acl = _web_acl(
            rules=[_sqli_rule(), _known_bad_inputs_rule()], rules_retrieved=False
        )
        result = _run_check({WEB_ACL_ARN: web_acl})
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert "rules could not be retrieved for Web ACLs" in result[0].status_extended

    def test_web_acls_could_not_be_listed(self):
        result = _run_check(
            {}, failed_scopes={"REGIONAL:eu-west-1", "CLOUDFRONT:us-east-1"}
        )
        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            result[0].status_extended
            == "Cannot evaluate AWS WAFv2 managed injection rule groups: Web ACLs could not be listed in CLOUDFRONT:us-east-1, REGIONAL:eu-west-1, verify that wafv2:ListWebACLs is granted to the scanning identity."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert result[0].resource_arn == AWS_ACCOUNT_ARN
        assert result[0].region == AWS_REGION_US_EAST_1

    def test_listing_failure_does_not_hide_evaluated_web_acls(self):
        rules = [_sqli_rule(), _known_bad_inputs_rule()]
        result = _run_check(
            {WEB_ACL_ARN: _web_acl(rules=rules)},
            failed_scopes={"REGIONAL:eu-west-2"},
        )
        assert len(result) == 2
        assert result[0].status == "PASS"
        assert result[0].resource_arn == WEB_ACL_ARN
        assert result[0].status_extended == PASS_MESSAGE
        assert result[1].status == "MANUAL"
        assert result[1].resource_id == AWS_ACCOUNT_NUMBER

    def test_listing_and_reading_failures_produce_one_manual_finding(self):
        other_arn = f"arn:aws:wafv2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:regional/webacl/other-acl/def"
        web_acls = {
            WEB_ACL_ARN: _web_acl(rules=[_sqli_rule(), _known_bad_inputs_rule()]),
            other_arn: _web_acl(arn=other_arn, name="other-acl", rules_retrieved=False),
        }
        result = _run_check(web_acls, failed_scopes={"REGIONAL:eu-west-2"})
        assert len(result) == 2
        assert result[0].status == "PASS"
        assert result[0].resource_arn == WEB_ACL_ARN
        assert result[1].status == "MANUAL"
        assert (
            result[1].status_extended
            == f"Cannot evaluate AWS WAFv2 managed injection rule groups: Web ACLs could not be listed in REGIONAL:eu-west-2, verify that wafv2:ListWebACLs is granted to the scanning identity; rules could not be retrieved for Web ACLs other-acl (REGIONAL:{AWS_REGION_EU_WEST_1}), verify that wafv2:GetWebACL is granted to the scanning identity."
        )
        assert result[1].resource_id == AWS_ACCOUNT_NUMBER
        assert result[1].resource_arn == AWS_ACCOUNT_ARN

    @mock_aws
    def test_both_rule_groups_enforced_with_moto(self):
        web_acl, result = _run_check_with_moto(
            [
                _api_managed_rule("AWSManagedRulesSQLiRuleSet", 0, "None"),
                _api_managed_rule("AWSManagedRulesKnownBadInputsRuleSet", 1, "None"),
            ]
        )
        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == PASS_MESSAGE
        assert result[0].resource_id == web_acl["Id"]
        assert result[0].resource_arn == web_acl["ARN"]
        assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_rule_group_overridden_to_count_with_moto(self):
        web_acl, result = _run_check_with_moto(
            [
                _api_managed_rule("AWSManagedRulesSQLiRuleSet", 0, "Count"),
                _api_managed_rule("AWSManagedRulesKnownBadInputsRuleSet", 1, "None"),
            ]
        )
        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"AWS WAFv2 Web ACL {WEB_ACL_NAME} does not enforce the AWS managed injection rule groups: AWSManagedRulesSQLiRuleSet is overridden to Count."
        )
        assert result[0].resource_arn == web_acl["ARN"]
