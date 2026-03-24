from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.security.security_client import security_client


class security_waf_enabled(Check):
    """Check if the Vercel Web Application Firewall (WAF) is enabled.

    This class verifies whether each Vercel project has the Web Application
    Firewall enabled to protect against common web attacks.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel WAF Enabled check.

        Iterates over all firewall configurations and checks if the WAF
        is enabled for each project.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for config in security_client.firewall_configs.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=config)

            if config.managed_rulesets is None:
                # 403 — plan limitation, cannot determine WAF status
                report.status = "MANUAL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"could not be checked for WAF status due to plan limitations. "
                    f"Manual verification is required."
                )
            elif config.firewall_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"has the Web Application Firewall enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"does not have the Web Application Firewall enabled."
                )

            findings.append(report)

        return findings
