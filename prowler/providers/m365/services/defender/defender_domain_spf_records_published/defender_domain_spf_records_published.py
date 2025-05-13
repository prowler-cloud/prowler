from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_domain_spf_records_published(Check):
    """
    Check if SPF records are published for all Exchange Online domains.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if SPF records are published for all domains.

        This method checks the DNS configuration for each domain to determine if the SPF record is present.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for domain_id, domain in defender_client.domain_service_configurations.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name=domain_id,
                resource_id=domain_id,
            )
            report.status = "FAIL"
            report.status_extended = f"SPF record is not published on Exchange Online for domain with ID {domain_id}."

            for config in domain.service_configuration_records:
                if config.record_type == "Txt":
                    if config.text == "v=spf1 include:spf.protection.outlook.com -all":
                        report.status = "PASS"
                        report.status_extended = f"SPF record is published on Exchange Online for domain with ID {domain_id}."

            findings.append(report)

        return findings
