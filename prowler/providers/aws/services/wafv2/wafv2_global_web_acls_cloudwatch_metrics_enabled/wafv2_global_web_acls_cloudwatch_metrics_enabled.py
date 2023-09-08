from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

class wafv2_global_web_acls_cloudwatch_metrics_enabled(Check):
    def execute(self):
        findings = []
        for global_web_acl in wafv2_client.global_web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = global_web_acl.region
            report.resource_id = global_web_acl.id
            report.resource_arn = global_web_acl.arn
            
            if global_web_acl.cloudwatch_metrics_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Global AWS WAFv2 Web ACL {global_web_acl.id} has CloudWatch metrics enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Global AWS WAFv2 Web ACL {global_web_acl.id} does not have CloudWatch metrics enabled."
                )
            
            findings.append(report)

        return findings
