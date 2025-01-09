from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class wafv2_webacl_logging_enabled(Check):
    def execute(self):
        findings = []
        for web_acl in wafv2_client.web_acls.values():
            report = Check_Report_AWS(self.metadata())
            report.region = web_acl.region
            report.resource_id = web_acl.id
            report.resource_arn = web_acl.arn
            report.resource_tags = web_acl.tags

            if web_acl.logging_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} has logging enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"AWS WAFv2 Web ACL {web_acl.name} does not have logging enabled."
                )

            findings.append(report)

        return findings
