from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.defender.defender_client import (
    defender_client,
)


class defender_antispam_policy_inbound_no_allowed_domains(Check):
    """
    Check if the inbound anti-spam policies do not contain allowed domains in Microsoft 365 Defender.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the check to verify if inbound anti-spam policies do not contain allowed domains.

        This method checks each inbound anti-spam policy to determine if the AllowedSenderDomains
        list is empty or undefined.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []
        for policy in defender_client.inbound_spam_policies:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Inbound Spam Policy",
                resource_id=policy.identity,
            )
            report.status = "PASS"
            report.status_extended = f"Inbound anti-spam policy {policy.identity} does not contain allowed domains."

            if policy.allowed_sender_domains:
                report.status = "FAIL"
                report.status_extended = f"Inbound anti-spam policy {policy.identity} contains allowed domains: {policy.allowed_sender_domains}."

            findings.append(report)

        return findings
