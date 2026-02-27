from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.domain.domain_client import domain_client


class domain_dns_properly_configured(Check):
    """Check if domains have DNS properly configured.

    This class verifies whether each Vercel domain has its DNS records
    properly configured to point to Vercel's infrastructure.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Domain DNS Configuration check.

        Iterates over all domains and checks if DNS is properly configured.

        Returns:
            List[CheckReportVercel]: A list of reports for each domain.
        """
        findings = []
        for domain in domain_client.domains.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=domain,
                resource_name=domain.name,
                resource_id=domain.id or domain.name,
            )

            if domain.configured:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.name} has DNS properly configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Domain {domain.name} does not have DNS properly configured. "
                    f"The domain may not be resolving to Vercel's infrastructure."
                )

            findings.append(report)

        return findings
