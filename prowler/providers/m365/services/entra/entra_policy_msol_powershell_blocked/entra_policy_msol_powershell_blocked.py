"""Check if legacy MSOnline (MSOL) PowerShell module is blocked in the tenant."""

from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_msol_powershell_blocked(Check):
    """Ensure legacy MSOnline (MSOL) PowerShell is blocked in the tenant authorization policy.

    This check verifies the `block_msol_powershell` property of the authorization policy.
    The MSOnline and AzureAD PowerShell modules are retired and use a legacy endpoint
    that is less monitored than Microsoft Graph. Blocking them removes an unsupported
    administrative access channel.

    - PASS: blockMsolPowerShell is true.
    - FAIL: blockMsolPowerShell is false.
    - MANUAL: The authorization policy could not be read or the property is missing/null.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the MSOL PowerShell blocked check.

        Retrieves the authorization policy from the Microsoft Entra client and checks
        whether the 'block_msol_powershell' property is set to true.

        Returns:
            List[CheckReportM365]: A list containing a single check report with
            the pass/fail/manual status and description.
        """
        findings = []
        auth_policy = entra_client.authorization_policy

        if auth_policy is None:
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name="Authorization Policy",
                resource_id="authorizationPolicy",
            )
            report.status = "MANUAL"
            report.status_extended = "Cannot evaluate whether legacy MSOnline (MSOL) PowerShell is blocked: the authorization policy could not be retrieved. Verify that the Policy.Read.All permission is granted to the scanning application."
            findings.append(report)
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=auth_policy,
            resource_name=auth_policy.name,
            resource_id=auth_policy.id,
        )

        block_msol = getattr(auth_policy, "block_msol_powershell", None)

        if block_msol is None:
            report.status = "MANUAL"
            report.status_extended = "Legacy MSOnline (MSOL) PowerShell blocked status could not be determined from the tenant authorization policy."
        elif block_msol:
            report.status = "PASS"
            report.status_extended = "Legacy MSOnline (MSOL) PowerShell is blocked in the tenant authorization policy."
        else:
            report.status = "FAIL"
            report.status_extended = "Legacy MSOnline (MSOL) PowerShell is not blocked in the tenant authorization policy."

        findings.append(report)
        return findings
