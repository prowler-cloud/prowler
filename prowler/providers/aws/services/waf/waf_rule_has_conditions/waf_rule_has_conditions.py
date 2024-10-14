from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.waf_client import waf_client


class waf_webacl_has_rules_or_rule_groups(Check):
    def execute(self):
        findings = []
        for rule in waf_client.rules.values():
            report = Check_Report_AWS(self.metadata())
            report.region = rule.region
            report.resource_id = rule.id
            report.resource_arn = rule.arn
            # report.resource_tags = rule.tags
            report.status = "FAIL"
            report.status_extended = f"AWS WAF Classic Regional Rule {rule.id} does not have any rules or rule groups."

            if rule.predicates:
                report.status = "PASS"
                report.status_extended = f"AWS WAF Classic Regional Rule {rule.id} has at least one condition."

            findings.append(report)

        return findings
