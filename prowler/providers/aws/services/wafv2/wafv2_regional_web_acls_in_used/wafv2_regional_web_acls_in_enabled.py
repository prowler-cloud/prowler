# wafv2_regional_web_acls_in_used.py

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2_service import WAFv2RegionalWebACLs

class WAFv2RegionalWebAclsInUsed(Check):
    def execute(self):
        findings = []
        wafv2_service = WAFv2RegionalWebACLs(audit_info)

        # Access Web ACL properties and create findings
        for web_acl in wafv2_service.web_acls:
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            
            if web_acl.logging_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} has logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.id} does not have logging enabled."
                )
            
            findings.append(report)

        return findings
