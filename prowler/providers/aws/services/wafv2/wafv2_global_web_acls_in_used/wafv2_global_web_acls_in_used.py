from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client

class wafv2_global_web_acls_in_used(Check):
    def execute(self):
        findings = []
        for global_web_acl in wafv2_client.global_web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = global_web_acl.region
            report.resource_id = global_web_acl.id
            report.resource_arn = global_web_acl.arn
            
            # Assuming you have a way to determine if the global WAFv2 Web ACL is in use
            if global_web_acl.is_in_use:
                report.status = "PASS"
                report.status_extended = (
                    f"Global AWS WAFv2 Web ACL {global_web_acl.id} is in use."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Global AWS WAFv2 Web ACL {global_web_acl.id} is not in use."
                )
            
            findings.append(report)

        return findings
