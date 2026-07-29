from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client


class waf_regional_webacl_logging_enabled(Check):
    """Ensure AWS WAF Classic Regional Web ACLs have logging enabled.

    This check evaluates whether each AWS WAF Classic Regional Web ACL has logging
    enabled by verifying the presence of at least one log destination configured
    in its logging configuration.

    - PASS: The Web ACL has at least one log destination configured.
    - FAIL: The Web ACL has no log destinations configured (logging is disabled).
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the WAF Regional Web ACL logging enabled check.

        Iterates over all WAF Classic Regional Web ACLs and generates a report
        indicating whether each Web ACL has logging enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for acl in wafregional_client.web_acls.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=acl)
            report.status = "FAIL"
            report.status_extended = (
                f"AWS WAF Regional Web ACL {acl.name} does not have logging enabled."
            )

            if acl.logging_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"AWS WAF Regional Web ACL {acl.name} does have logging enabled."
                )

            findings.append(report)

        return findings
