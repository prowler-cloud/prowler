from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.domain.domain_client import domain_client


class domain_verified(Check):
    """Check if domains have been verified by Vercel.

    This class verifies whether each Vercel domain has passed ownership
    verification. Unverified domains may not function correctly and could
    indicate domain misconfiguration or hijacking attempts.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Domain Verified check.

        Iterates over all domains and checks if each is verified.

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

            if domain.verified:
                report.status = "PASS"
                report.status_extended = f"Domain {domain.name} is verified."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Domain {domain.name} is not verified. "
                    f"The domain may not be serving traffic correctly."
                )

            findings.append(report)

        return findings
