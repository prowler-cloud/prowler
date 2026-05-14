from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_zap_for_teams_enabled(Check):
    """Check if Zero-hour auto purge (ZAP) is enabled for Microsoft Teams.

    ZAP is a protection feature that retroactively detects and neutralizes malware
    and high confidence phishing in Teams messages.

    - PASS: ZAP is enabled for Teams protection.
    - FAIL: ZAP is not enabled for Teams protection.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for Teams ZAP protection status.

        This method checks if Zero-hour auto purge (ZAP) is enabled for Microsoft Teams
        to ensure malicious content is automatically removed from chats after detection.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        teams_protection_policy = defender_client.teams_protection_policy

        if teams_protection_policy:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=teams_protection_policy,
                resource_name="Teams Protection Policy",
                resource_id="teamsProtectionPolicy",
            )

            if teams_protection_policy.zap_enabled:
                report.status = "PASS"
                report.status_extended = (
                    "Zero-hour auto purge (ZAP) is enabled for Microsoft Teams."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "Zero-hour auto purge (ZAP) is not enabled for Microsoft Teams."
                )

            findings.append(report)

        return findings
