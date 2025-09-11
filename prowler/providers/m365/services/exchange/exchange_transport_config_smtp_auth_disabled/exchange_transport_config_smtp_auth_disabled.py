from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_transport_config_smtp_auth_disabled(Check):
    """Check if SMTP AUTH is disabled in Exchange Online Transport Config.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for SMTP AUTH setting in Transport Config.

        This method checks if SMTP AUTH is disabled at the organization level in Exchange Online.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        transport_config = exchange_client.transport_config
        if transport_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=transport_config,
                resource_name="Transport Configuration",
                resource_id="transport_config",
            )
            report.status = "FAIL"
            report.status_extended = (
                "SMTP AUTH is enabled in the Exchange Online Transport Config."
            )

            if transport_config.smtp_auth_disabled:
                report.status = "PASS"
                report.status_extended = (
                    "SMTP AUTH is disabled in the Exchange Online Transport Config."
                )

            findings.append(report)

        return findings
