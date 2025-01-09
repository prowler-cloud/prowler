from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.waf_client import waf_client


class waf_global_rulegroup_not_empty(Check):
    def execute(self):
        findings = []
        for rule_group in waf_client.rule_groups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = rule_group.region
            report.resource_id = rule_group.id
            report.resource_arn = rule_group.arn
            report.resource_tags = rule_group.tags
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Global Rule Group {rule_group.name} does not have any rules."
            )

            if rule_group.rules:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Global Rule Group {rule_group.name} is not empty."
                )

            findings.append(report)

        return findings
