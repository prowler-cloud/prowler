from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_safe_attachments_policy_enabled(Check):
    """
    Check if Safe Attachments policy is properly configured in Microsoft Defender for Office 365.

    This check verifies that the Built-In Protection Policy has:
    - Enable = True
    - Action = Block
    - QuarantineTag = AdminOnlyAccessPolicy

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the check for Safe Attachments policy configuration.

        This method evaluates the Safe Attachments policies in Microsoft Defender
        for Office 365 to ensure the Built-In Protection Policy is properly configured.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []

        # Case 1: No Safe Attachments policies exist
        if not defender_client.safe_attachments_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=defender_client,
                resource_name="Safe Attachments",
                resource_id="safe_attachments_policies",
            )
            report.status = "FAIL"
            report.status_extended = (
                "No Safe Attachments policies found. Safe Attachments provides "
                "protection against malicious email attachments and requires "
                "Microsoft Defender for Office 365 (Plan 1 or Plan 2) licensing."
            )
            findings.append(report)
            return findings

        for policy in defender_client.safe_attachments_policies:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=policy,
                resource_name=policy.name,
                resource_id=policy.identity,
            )

            # Check if this is the Built-In Protection Policy
            if policy.name == "Built-In Protection Policy":
                misconfigured_settings = []

                if not policy.enable:
                    misconfigured_settings.append("Enable is not True")

                if policy.action != "Block":
                    misconfigured_settings.append(
                        f"Action is {policy.action}, not Block"
                    )

                if policy.quarantine_tag != "AdminOnlyAccessPolicy":
                    misconfigured_settings.append(
                        f"QuarantineTag is {policy.quarantine_tag}, not AdminOnlyAccessPolicy"
                    )

                if misconfigured_settings:
                    # Case 2: Built-In Protection Policy exists but is not properly configured
                    report.status = "FAIL"
                    report.status_extended = f"Safe Attachments Built-In Protection Policy is not properly configured: {'; '.join(misconfigured_settings)}."
                else:
                    # Case 3: Built-In Protection Policy exists and is properly configured
                    report.status = "PASS"
                    report.status_extended = "Safe Attachments Built-In Protection Policy is properly configured with Enable=True, Action=Block, and QuarantineTag=AdminOnlyAccessPolicy."
            else:
                # For other policies, check if they have secure settings
                if policy.enable and policy.action == "Block":
                    # Case 4: Custom policy is enabled with secure settings
                    report.status = "PASS"
                    report.status_extended = f"Safe Attachments policy {policy.name} is enabled with Action=Block."
                elif not policy.enable:
                    # Case 5: Custom policy is not enabled
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Safe Attachments policy {policy.name} is not enabled."
                    )
                else:
                    # Case 6: Custom policy is enabled but with less secure action
                    report.status = "FAIL"
                    report.status_extended = f"Safe Attachments policy {policy.name} has Action={policy.action}, which is less secure than Block."

            findings.append(report)

        return findings
