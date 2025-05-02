from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_organization_mailtips_enabled(Check):
    """
    Check if MailTips are enabled for Exchange Online.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check for MailTips in Exchange Online.

        This method checks if MailTips are enabled in the Exchange organization configuration.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        organization_config = exchange_client.organization_config
        if organization_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=organization_config,
                resource_name=organization_config.name,
                resource_id=organization_config.guid,
            )
            report.status = "FAIL"
            report.status_extended = (
                "MailTips are not fully enabled for Exchange Online."
            )

            if (
                organization_config.mailtips_enabled
                and organization_config.mailtips_external_recipient_enabled
                and organization_config.mailtips_group_metrics_enabled
                and organization_config.mailtips_large_audience_threshold
                <= exchange_client.audit_config.get(
                    "recommended_mailtips_large_audience_threshold", 25
                )
            ):
                report.status = "PASS"
                report.status_extended = (
                    "MailTips are fully enabled for Exchange Online."
                )

            findings.append(report)

        return findings
