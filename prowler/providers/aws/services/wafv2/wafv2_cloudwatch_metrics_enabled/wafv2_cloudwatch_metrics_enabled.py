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

            if (
                web_acl.pre_process_firewall_rule_groups
                or web_acl.post_process_firewall_rule_groups
                or web_acl.rules
            ):
                report.status = "PASS"
                report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does have CloudWatch Metrics enabled in all rule groups and rules."

                # Pre-Process Rule Groups
                pre_rg_metrics_disabled = []
                for rule_group in web_acl.pre_process_firewall_rule_groups:
                    if not rule_group.cloudwatch_metrics_enabled:
                        report.status = "FAIL"
                        pre_rg_metrics_disabled.append(rule_group.name)

                # Post-Process Rule Groups
                post_rg_metrics_disabled = []
                for rule_group in web_acl.post_process_firewall_rule_groups:
                    if not rule_group.cloudwatch_metrics_enabled:
                        report.status = "FAIL"
                        post_rg_metrics_disabled.append(rule_group.name)

                # Rules
                rules_metrics_disabled = []
                for rule in web_acl.rules:
                    if not rule.cloudwatch_metrics_enabled:
                        report.status = "FAIL"
                        rules_metrics_disabled.append(rule.name)

                if report.status == "FAIL":
                    report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch Metrics enabled in all rule groups and rules.\n\t\t\tNon compliant reources are:"
                    if pre_rg_metrics_disabled:
                        report.status_extended += f"\n\t\t\t\t· Pre-Process Rule Groups: {", ".join(pre_rg_metrics_disabled)}."
                    if post_rg_metrics_disabled:
                        report.status_extended += f"\n\t\t\t\t· Post-Process Rule Groups: {", ".join(post_rg_metrics_disabled)}."
                    if rules_metrics_disabled:
                        report.status_extended += (
                            f"\n\t\t\t\t· Rules: {", ".join(rules_metrics_disabled)}."
                        )

                findings.append(report)

        return findings
