from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client
from prowler.providers.aws.services.wafv2.wafv2_service import Scope

AWS_MANAGED_RULE_GROUP_VENDOR = "AWS"
REQUIRED_INJECTION_RULE_GROUPS = (
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
)


class wafv2_webacl_managed_injection_rule_groups_enabled(Check):
    """Ensure WAFv2 Web ACLs enforce the AWS managed injection rule groups.

    A Web ACL passes when both ``AWSManagedRulesSQLiRuleSet`` and
    ``AWSManagedRulesKnownBadInputsRuleSet`` are referenced by one of its
    rules, directly or through an AWS Firewall Manager rule group, and that
    rule does not override the group's actions to ``Count``: a counted rule
    group only records matches and blocks nothing.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check.

        Returns:
            One PASS or FAIL report per Web ACL whose rules were read, plus a
            single account-level MANUAL report when Web ACLs could not be
            listed in some scope or their rules could not be retrieved.
        """
        findings = []
        unreadable_web_acls = []

        for web_acl in wafv2_client.web_acls.values():
            if not web_acl.rules_retrieved:
                unreadable_web_acls.append(web_acl)
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            enforced = set()
            counted = set()
            for rule in web_acl.rules + web_acl.rule_groups:
                managed_rule_group = rule.managed_rule_group
                if (
                    managed_rule_group
                    and managed_rule_group.vendor_name == AWS_MANAGED_RULE_GROUP_VENDOR
                    and managed_rule_group.name in REQUIRED_INJECTION_RULE_GROUPS
                ):
                    if rule.overridden_to_count:
                        counted.add(managed_rule_group.name)
                    else:
                        enforced.add(managed_rule_group.name)

            issues = []
            for rule_group_name in REQUIRED_INJECTION_RULE_GROUPS:
                if rule_group_name in enforced:
                    continue
                if rule_group_name in counted:
                    issues.append(f"{rule_group_name} is overridden to Count")
                else:
                    issues.append(f"{rule_group_name} is missing")

            if issues:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} does not enforce the AWS "
                    f"managed injection rule groups: {', '.join(issues)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} enforces the AWS managed "
                    f"injection rule groups "
                    f"{' and '.join(REQUIRED_INJECTION_RULE_GROUPS)}."
                )

            findings.append(report)

        problems = []
        failed_scopes = wafv2_client.web_acls_list_failed_scopes
        if failed_scopes:
            problems.append(
                f"Web ACLs could not be listed in {', '.join(sorted(failed_scopes))}, "
                f"verify that wafv2:ListWebACLs is granted to the scanning identity"
            )
        if unreadable_web_acls:
            unreadable_names = sorted(
                f"{web_acl.name} ({web_acl.scope.value}:{web_acl.region})"
                for web_acl in unreadable_web_acls
            )
            cloudfront_hint = (
                " and that us-east-1 is included in the scan for CLOUDFRONT Web ACLs"
                if any(
                    web_acl.scope == Scope.CLOUDFRONT for web_acl in unreadable_web_acls
                )
                else ""
            )
            problems.append(
                f"rules could not be retrieved for Web ACLs "
                f"{', '.join(unreadable_names)}, verify that wafv2:GetWebACL is "
                f"granted to the scanning identity{cloudfront_hint}"
            )

        if problems:
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = wafv2_client.region
            report.resource_id = wafv2_client.audited_account
            report.resource_arn = wafv2_client.audited_account_arn
            report.status = "MANUAL"
            report.status_extended = (
                f"Cannot evaluate AWS WAFv2 managed injection rule groups: "
                f"{'; '.join(problems)}."
            )
            findings.append(report)

        return findings
