from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.security.security_client import security_client


class security_rate_limiting_configured(Check):
    """Check if rate limiting rules are configured for each project.

    This class verifies whether each Vercel project has at least one rate
    limiting rule configured to protect against abuse and DDoS attacks.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Rate Limiting Configuration check.

        Iterates over all firewall configurations and checks if at least
        one rate limiting rule is present.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for config in security_client.firewall_configs.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=config)

            if config.rate_limiting_rules:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"has {len(config.rate_limiting_rules)} rate limiting rule(s) configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"does not have any rate limiting rules configured."
                )

            findings.append(report)

        return findings
