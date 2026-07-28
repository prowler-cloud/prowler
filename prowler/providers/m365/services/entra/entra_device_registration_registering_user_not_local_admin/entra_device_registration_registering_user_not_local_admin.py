from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client
from prowler.providers.m365.services.entra.entra_service import (
    DeviceRegistrationMembershipType,
)

RESTRICTED_MEMBERSHIP_TYPES = {
    DeviceRegistrationMembershipType.ENUMERATED.value,
    DeviceRegistrationMembershipType.NONE.value,
}


class entra_device_registration_registering_user_not_local_admin(Check):
    """Check if the registering user is not added as local admin on Entra join.

    The device registration policy should restrict which registering users are added
    to the local administrators group during Microsoft Entra join to Selected users
    or None, rather than all registering users.

    - PASS: Registering users are restricted (Selected or None) from becoming local
      administrators on Entra join.
    - FAIL: All registering users are added as local administrators on Entra join.
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
            "All registering users are added as local administrators on devices "
            "during Microsoft Entra join."
        )

        if policy.azure_ad_join_registering_users_type in RESTRICTED_MEMBERSHIP_TYPES:
            report.status = "PASS"
            report.status_extended = (
                "Registering users are restricted from being added as local "
                "administrators on devices during Microsoft Entra join."
            )

        findings.append(report)
        return findings
