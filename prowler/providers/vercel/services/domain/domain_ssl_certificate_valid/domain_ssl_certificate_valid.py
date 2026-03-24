from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.domain.domain_client import domain_client


class domain_ssl_certificate_valid(Check):
    """Check if domains have a valid SSL certificate provisioned.

    This class verifies whether each Vercel domain has an SSL certificate
    provisioned. Vercel auto-provisions SSL for configured domains, so a
    missing certificate may indicate a configuration issue.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Domain SSL Certificate check.

        Iterates over all domains and checks if an SSL certificate is present.

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

            if domain.ssl_certificate is not None:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.name} has an SSL certificate provisioned."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Domain {domain.name} does not have an SSL certificate provisioned."

            findings.append(report)

        return findings
