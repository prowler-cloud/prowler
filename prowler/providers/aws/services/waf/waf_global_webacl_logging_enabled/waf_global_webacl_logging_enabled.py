from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.waf_client import waf_client


class waf_global_webacl_logging_enabled(Check):
    def execute(self):
        findings = []
        for acl in waf_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=acl)
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Global Web ACL {acl.name} does not have logging enabled."
            )

            if acl.logging_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Global Web ACL {acl.name} does have logging enabled."
                )

            findings.append(report)

        return findings
