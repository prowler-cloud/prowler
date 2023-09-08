from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

class wafv2_web_acls_cloudwatch_metrics_enabled(Check):
    def _prepare_report_metadata(self, web_acl):
        metadata = self.metadata()
        metadata["SubServiceName"] = "WAFv2"
        metadata["ResourceIdTemplate"] = web_acl.id
        metadata["RelatedUrl"] = "URL to relevant documentation"
        metadata["Remediation"]["Code"]["NativeIaC"] = "Remediation code for Infrastructure as Code"
        metadata["Remediation"]["Code"]["Other"] = "Other remediation code"
        return metadata

    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            
            if web_acl.cloudwatch_metrics_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} has CloudWatch metrics enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} does not have CloudWatch metrics enabled."
                )
            
            findings.append(report)

        return findings
