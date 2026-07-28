from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_device_registration_global_admins_not_local_admins(Check):
    """Check if Global Administrators are not added as local admins on Entra join.

    The device registration policy should not automatically add the Global
    Administrator role to the local administrators group of a device during the
    Microsoft Entra join process.

    - PASS: Global Administrators are not added as local administrators on Entra join.
    - FAIL: Global Administrators are added as local administrators on Entra join.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        policy = entra_client.device_registration_policy
        if not policy:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=policy,
            resource_name="Device Registration Policy",
            resource_id="deviceRegistrationPolicy",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Global Administrators are added as local administrators on devices "
            "during Microsoft Entra join."
        )

        if policy.azure_ad_join_global_admins_enabled is False:
            report.status = "PASS"
            report.status_extended = (
                "Global Administrators are not added as local administrators on "
                "devices during Microsoft Entra join."
            )

        findings.append(report)
        return findings
