from typing import List

from prowler.lib.check.models import Check, CheckReportMicrosoft365
from prowler.providers.microsoft365.services.defender.defender_client import (
    defender_client,
)


class defender_policy_common_attachments_filter_enabled(Check):
    """
    Check if the Common Attachment Types Filter is enabled in the Defender anti-malware policy.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportMicrosoft365]:
        """
        Execute the check to verify if the Common Attachment Types Filter is enabled.

        This method checks the Defender anti-malware policy to determine if the
        Common Attachment Types Filter is enabled.

        Returns:
            List[CheckReportMicrosoft365]: A list of reports containing the result of the check.
        """
        findings = []
        for policy in defender_client.malware_policies:
            report = CheckReportMicrosoft365(
                metadata=self.metadata(),
                resource=policy,
                resource_name="Defender Malware Policy",
                resource_id="defenderMalwarePolicy",
            )
            report.status = "FAIL"
            report.status_extended = f"Common Attachment Types Filter is not enabled in the Defender anti-malware policy {policy.identity}."

            if policy.enable_file_filter:
                report.status = "PASS"
                report.status_extended = f"Common Attachment Types Filter is enabled in the Defender anti-malware policy {policy.identity}."

            findings.append(report)

        return findings
