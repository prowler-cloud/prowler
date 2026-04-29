from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.lib.billing import plan_reason_suffix
from prowler.providers.vercel.services.security.security_client import security_client


class security_managed_rulesets_enabled(Check):
    """Check if managed WAF rulesets are enabled for each project.

    This class verifies whether each Vercel project has managed rulesets
    enabled. Managed rulesets provide curated protection rules maintained
    by Vercel against known attack patterns. This feature is plan-gated
    and may not be available on all plans.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Managed Rulesets Enabled check.

        Iterates over all firewall configurations and checks if managed
        rulesets are enabled. Reports MANUAL status when the firewall
        configuration cannot be assessed from the API.

        Returns:
            List[CheckReportVercel]: A list of reports for each project.
        """
        findings = []
        for config in security_client.firewall_configs.values():
            report = CheckReportVercel(metadata=self.metadata(), resource=config)

            if not config.firewall_config_accessible:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"could not be assessed for managed rulesets because the "
                    f"firewall configuration endpoint was not accessible. "
                    f"Manual verification is required."
                    f"{plan_reason_suffix(config.billing_plan, {'hobby', 'pro'}, 'some managed WAF rulesets, including the OWASP Core Ruleset, are only available on Vercel Enterprise plans.')}"
                )
            elif config.managed_rulesets:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"has managed WAF rulesets enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Project {config.project_name} ({config.project_id}) "
                    f"does not have managed WAF rulesets enabled."
                )

            findings.append(report)

        return findings
