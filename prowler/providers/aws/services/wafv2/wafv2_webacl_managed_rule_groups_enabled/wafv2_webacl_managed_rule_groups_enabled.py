from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_managed_rule_groups_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=web_acl)
            managed_rule_groups = [
                f"{rule.managed_rule_group.vendor_name}/{rule.managed_rule_group.name}"
                for rule in web_acl.rules
                if rule.managed_rule_group
            ]
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAFv2 Web ACL {web_acl.name} does not use any managed rule group."
            )

            if managed_rule_groups:
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} uses managed rule groups: {', '.join(managed_rule_groups)}."

            findings.append(report)

        return findings
