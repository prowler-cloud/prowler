from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.exchange.exchange_client import exchange_client


class exchange_external_mail_tagged(Check):
    """Ensure email from external senders is identified.

    This check verifies that the native "External" sender tag feature is enabled
    in Exchange so that messages from outside the organization are automatically marked.
    """

    def execute(self) -> List[CheckReportM365]:
        """Run the check to validate that external sender tagging is enabled.

        Iterates through the external mail configuration to determine if the
        ExternalInOutlook setting is turned on and generates a report accordingly.

        Returns:
            List[CheckReportM365]: A list of reports for each organization identity.
        """
        findings = []

        for mail_config in exchange_client.external_mail_config:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=mail_config,
                resource_name=mail_config.identity,
                resource_id=mail_config.identity,
            )
            report.status = "FAIL"
            report.status_extended = f"External sender tagging is disabled for Exchange identity {mail_config.identity}."

            if mail_config.external_mail_tag_enabled:
                report.status = "PASS"
                report.status_extended = f"External sender tagging is enabled for Exchange identity {mail_config.identity}."

            findings.append(report)

        return findings
