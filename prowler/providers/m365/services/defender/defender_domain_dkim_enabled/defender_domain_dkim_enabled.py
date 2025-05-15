from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_domain_dkim_enabled(Check):
    """
    Check if DKIM is enabled for all Exchange Online domains.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if DKIM is enabled for all domains.

        This method checks the DKIM signing configuration for each domain to determine if DKIM is enabled.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for config in defender_client.dkim_configurations:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=config,
                resource_name="DKIM Configuration",
                resource_id=config.id,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"DKIM is not enabled for domain with ID {config.id}."
            )

            if config.dkim_signing_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"DKIM is enabled for domain with ID {config.id}."
                )

            findings.append(report)

        return findings
