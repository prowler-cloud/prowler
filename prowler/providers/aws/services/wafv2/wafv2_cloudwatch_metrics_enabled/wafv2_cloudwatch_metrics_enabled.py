from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_cloudwatch_metrics_enabled(Check):
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
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does have CloudWatch Metrics enabled in all rule groups and rules."

                # Rules
                rules_metrics_disabled = []
                for rule in web_acl.rules:
                    if not rule.cloudwatch_metrics_enabled:
                        report.status = "FAIL"
                        rules_metrics_disabled.append(rule.name)

                # Rule Groups
                rule_groups_metrics_disabled = []
                for rule_group in web_acl.rule_groups:
                    if not rule_group.cloudwatch_metrics_enabled:
                        report.status = "FAIL"
                        rule_groups_metrics_disabled.append(rule_group.name)

                if report.status == "FAIL":
                    if rules_metrics_disabled and rule_groups_metrics_disabled:
                        report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch Metrics enabled in all rule groups and rules. Non compliant resources are: Rules: {', '.join(rules_metrics_disabled)}. Rule Groups: {', '.join(rule_groups_metrics_disabled)}."
                    elif rules_metrics_disabled:
                        report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch Metrics enabled in all rule groups and rules. Non compliant resources are: Rules: {', '.join(rules_metrics_disabled)}."
                    elif rule_groups_metrics_disabled:
                        report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch Metrics enabled in all rule groups and rules. Non compliant resources are: Rule Groups: {', '.join(rule_groups_metrics_disabled)}."

                findings.append(report)

        return findings
