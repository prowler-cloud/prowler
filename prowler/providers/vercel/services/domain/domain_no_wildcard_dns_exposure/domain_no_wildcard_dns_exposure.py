from typing import List

from prowler.lib.check.models import Check, CheckReportVercel
from prowler.providers.vercel.services.domain.domain_client import domain_client


class domain_no_wildcard_dns_exposure(Check):
    """Check if domains have wildcard DNS records that could expose subdomains.

    This class verifies whether any Vercel domain has wildcard DNS records
    (e.g., *.example.com) that could inadvertently route traffic to the
    application from any subdomain.
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Domain Wildcard DNS Exposure check.

        Iterates over all domains and inspects DNS records for wildcard entries.

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

            wildcard_records = []
            for record in domain.dns_records:
                record_name = record.get("name", "")
                if record_name == "*" or record_name.startswith("*."):
                    wildcard_records.append(record_name)

            if not wildcard_records:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.name} has no wildcard DNS records."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Domain {domain.name} has {len(wildcard_records)} wildcard DNS "
                    f"record(s): {', '.join(wildcard_records)}. This may expose "
                    f"unintended subdomains."
                )

            findings.append(report)

        return findings
