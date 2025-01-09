from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_rule_logging_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            report.resource_tags = web_acl.tags

            if web_acl.rules or web_acl.rule_groups:
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does have CloudWatch Metrics enabled in all its rules."

                rules_metrics_disabled = []
                for rule in web_acl.rules:
                    if not rule.cloudwatch_metrics_enabled:
                        rules_metrics_disabled.append(rule.name)

                rule_groups_metrics_disabled = []
                for rule_group in web_acl.rule_groups:
                    if not rule_group.cloudwatch_metrics_enabled:
                        rule_groups_metrics_disabled.append(rule_group.name)

                if rules_metrics_disabled and rule_groups_metrics_disabled:
                    report.status = "FAIL"
                    report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does not have CloudWatch Metrics enabled in rules: {', '.join(rules_metrics_disabled)} nor in rule groups: {', '.join(rule_groups_metrics_disabled)}."
                elif rules_metrics_disabled:
                    report.status = "FAIL"
                    report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does not have CloudWatch Metrics enabled in rules: {', '.join(rules_metrics_disabled)}."
                elif rule_groups_metrics_disabled:
                    report.status = "FAIL"
                    report.status_extended = f"AWS WAFv2 Web ACL {web_acl.name} does not have CloudWatch Metrics enabled in rule groups: {', '.join(rule_groups_metrics_disabled)}."

                findings.append(report)

        return findings
