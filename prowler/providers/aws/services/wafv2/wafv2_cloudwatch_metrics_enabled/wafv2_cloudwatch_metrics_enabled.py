from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_cloudwatch_metrics_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            report.resource_tags = web_acl.tags
            report.status = "FAIL"
            report.status_extended = f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch Metrics enabled."

            if web_acl.cloudwatch_metrics_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} has CloudWatch Metrics enabled."
                )

            findings.append(report)

        return findings
