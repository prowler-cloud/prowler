from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client


class waf_regional_rule_with_conditions(Check):
    def execute(self):
        findings = []
        for rule in wafregional_client.rules.values():
            report = Check_Report_AWS(self.metadata())
            report.region = rule.region
            report.resource_id = rule.id
            report.resource_arn = rule.arn
            report.resource_tags = rule.tags
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Regional Rule {rule.name} does not have any conditions."
            )

            if rule.predicates:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Regional Rule {rule.name} has at least one condition."
                )

            findings.append(report)

        return findings
