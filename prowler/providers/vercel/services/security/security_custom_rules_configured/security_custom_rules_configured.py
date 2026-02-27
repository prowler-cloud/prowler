from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.security.security_client import security_client


class security_custom_rules_configured(Check):
    """Check if custom firewall rules are configured for each project.

    This class verifies whether each Vercel project has at least one
    custom firewall rule configured for application-specific protection.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Custom Rules Configuration check.

        Iterates over all firewall configurations and checks if at least
        one custom rule is present.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for config in security_client.firewall_configs.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=config)

            if config.custom_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"has {len(config.custom_rules)} custom firewall rule(s) configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"does not have any custom firewall rules configured."
                )

            findings.append(report)

        return findings
