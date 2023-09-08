from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

class wafv2_web_acls_sampling_request_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            
            if web_acl.sampling_request_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} has sampling of requests enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} does not have sampling of requests enabled."
                )
            
            findings.append(report)

        return findings
