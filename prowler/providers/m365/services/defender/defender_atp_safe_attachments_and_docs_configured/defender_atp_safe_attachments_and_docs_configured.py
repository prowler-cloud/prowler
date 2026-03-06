from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_atp_safe_attachments_and_docs_configured(Check):
    """
    Check if Safe Attachments for SharePoint, OneDrive, and Teams is properly configured.

    This check verifies that the ATP (Advanced Threat Protection) policy for Office 365 has:
    - EnableATPForSPOTeamsODB = True (Safe Attachments enabled for SPO/OneDrive/Teams)
    - EnableSafeDocs = True (Safe Documents enabled)
    - AllowSafeDocsOpen = False (Users cannot bypass Protected View for malicious files)

    - PASS: All three settings are properly configured.
    - FAIL: One or more settings are not properly configured.
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify Safe Attachments ATP policy configuration.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        if defender_client.advanced_threat_protection_policy:
            policy = defender_client.advanced_threat_protection_policy

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.identity,
                resource_id=policy.identity,
            )

            # Check all three required settings
            is_atp_enabled = policy.enable_atp_for_spo_teams_odb
            is_safe_docs_enabled = policy.enable_safe_docs
            is_safe_docs_open_blocked = not policy.allow_safe_docs_open

            if is_atp_enabled and is_safe_docs_enabled and is_safe_docs_open_blocked:
                # Case 1: ATP policy exists and is properly configured
                report.status = "PASS"
                report.status_extended = f"ATP policy {policy.identity} has Safe Attachments for SharePoint, OneDrive, and Teams properly configured with Safe Documents enabled and click-through blocked."
            else:
                # Case 2: ATP policy exists but is not properly configured
                report.status = "FAIL"
                issues = []
                if not is_atp_enabled:
                    issues.append("Safe Attachments for SPO/OneDrive/Teams is disabled")
                if not is_safe_docs_enabled:
                    issues.append("Safe Documents is disabled")
                if not is_safe_docs_open_blocked:
                    issues.append("users can bypass Protected View for malicious files")
                report.status_extended = f"ATP policy {policy.identity} is not properly configured: {'; '.join(issues)}."

            findings.append(report)

        return findings
