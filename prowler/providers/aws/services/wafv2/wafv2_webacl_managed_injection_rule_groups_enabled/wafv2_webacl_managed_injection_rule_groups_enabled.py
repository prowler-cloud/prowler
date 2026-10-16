from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

# AWS managed rule groups that protect against common injection-style attacks.
REQUIRED_MANAGED_RULE_GROUPS = {
    "AWSManagedRulesSQLiRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
}


class wafv2_webacl_managed_injection_rule_groups_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)

            # A managed rule group is considered enabled when it is referenced by the Web
            # ACL, owned by AWS, and not excluded wholesale (its whole action overridden to
            # Count).
            enabled_groups = {
                managed_rule_group.name
                for managed_rule_group in web_acl.managed_rule_groups
                if managed_rule_group.vendor_name == "AWS"
                and not managed_rule_group.override_to_count
            }

            missing_groups = sorted(REQUIRED_MANAGED_RULE_GROUPS - enabled_groups)

            if not missing_groups:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} has the AWS managed injection rule "
                    "groups AWSManagedRulesSQLiRuleSet and AWSManagedRulesKnownBadInputsRuleSet enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} does not have the following AWS managed "
                    f"injection rule groups enabled: {', '.join(missing_groups)}."
                )

            findings.append(report)

        return findings
