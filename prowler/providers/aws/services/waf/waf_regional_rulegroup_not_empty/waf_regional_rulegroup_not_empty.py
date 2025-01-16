from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client


class waf_regional_rulegroup_not_empty(Check):
    def execute(self):
        findings = []
        for rule_group in wafregional_client.rule_groups.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=rule_group
            )
            report.status = "FAIL"
            report.status_extended = f"AWS WAF Regional Rule Group {rule_group.name} does not have any rules."

            if rule_group.rules:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Regional Rule Group {rule_group.name} is not empty."
                )

            findings.append(report)

        return findings
