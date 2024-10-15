from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client


class waf_webacl_has_rules_or_rule_groups(Check):
    def execute(self):
        findings = []
        for acl in wafregional_client.web_acls.values():
            report = Check_Report_AWS(self.metadata())
            report.region = acl.region
            report.resource_id = acl.id
            report.resource_arn = acl.arn
            report.resource_tags = acl.tags
            report.status = "FAIL"
            report.status_extended = f"AWS WAFRegional Web ACL {acl.id} does not have any rules or rule groups."

            if acl.rules or acl.rule_groups:
                report.status = "PASS"
                report.status_extended = f"AWS WAFRegional Web ACL {acl.id} has at least one rule or rule group."

            findings.append(report)

        return findings
