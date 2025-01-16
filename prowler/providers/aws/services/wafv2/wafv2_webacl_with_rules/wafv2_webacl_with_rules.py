from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_with_rules(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=web_acl
            )
            report.status = "FAIL"
            report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does not have any rules or rule groups attached."

            if web_acl.rules or web_acl.rule_groups:
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does have rules or rule groups attached."

            findings.append(report)

        return findings
