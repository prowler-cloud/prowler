from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client


class waf_rulegroup_has_rules(Check):
    def execute(self):
        findings = []
        for rule_group in wafregional_client.rule_groups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = rule_group.region
            report.resource_id = rule_group.id
            report.resource_arn = rule_group.arn
            report.resource_tags = rule_group.tags
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Regional Rule Group {rule_group.id} does not have any rules."
            )

            if rule_group.rules:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Regional Rule Group {rule_group.id} is not empty."
                )

            findings.append(report)

        return findings
