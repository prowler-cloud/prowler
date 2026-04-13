from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.security.security_client import security_client


class security_ip_blocking_rules_configured(Check):
    """Check if IP blocking rules are configured for each project.

    This class verifies whether each Vercel project has at least one IP
    blocking rule configured to restrict access from known malicious
    IP addresses or ranges.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel IP Blocking Rules Configuration check.

        Iterates over all firewall configurations and checks if at least
        one IP blocking rule is present.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for config in security_client.firewall_configs.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=config)

            if config.ip_blocking_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"has {len(config.ip_blocking_rules)} IP blocking rule(s) configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"does not have any IP blocking rules configured. "
                    f"This feature is only available on Vercel Pro/Enterprise plans."
                )

            findings.append(report)

        return findings
