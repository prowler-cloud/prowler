from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_policy_default_user_cannot_read_bitlocker_keys(Check):
    """Check if default users are restricted from reading BitLocker keys for their owned devices.

    This check verifies whether the authorization policy prevents non-admin users
    from self-recovering BitLocker keys for devices they own in Microsoft Entra ID.

    - PASS: Non-admin users cannot read BitLocker keys for their owned devices.
    - FAIL: Non-admin users are allowed to read BitLocker keys for their owned devices.
    """

    def execute(self) -> List[CheckReportM365]:
        """Execute the check for BitLocker key self-recovery restrictions.

        Returns:
            List[CheckReportM365]: A list containing the result of the check.
        """
        findings = []
        auth_policy = entra_client.authorization_policy

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=auth_policy if auth_policy else {},
            resource_name=auth_policy.name if auth_policy else "Authorization Policy",
            resource_id=auth_policy.id if auth_policy else "authorizationPolicy",
        )
        report.status = "FAIL"
        report.status_extended = "Non-admin users are allowed to read BitLocker keys for their owned devices."

        if getattr(
            entra_client.authorization_policy, "default_user_role_permissions", None
        ) and not getattr(
            entra_client.authorization_policy.default_user_role_permissions,
            "allowed_to_read_bitlocker_keys_for_owned_device",
            True,
        ):
            report.status = "PASS"
            report.status_extended = "Non-admin users are not allowed to read BitLocker keys for their owned devices."

        findings.append(report)
        return findings
