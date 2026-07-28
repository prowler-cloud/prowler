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


class entra_device_registration_join_restricted(Check):
    """Check if the users allowed to join devices to Entra are restricted.

    The device registration policy should restrict who can register devices as
    Microsoft Entra joined to Selected users or None, rather than allowing all
    users.

    - PASS: Only selected users or no users may join devices to Entra.
    - FAIL: All users may join devices to Entra.
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
            "All users are allowed to join devices to Microsoft Entra."
        )

        if policy.azure_ad_join_allowed_to_join_type in RESTRICTED_MEMBERSHIP_TYPES:
            report.status = "PASS"
            report.status_extended = (
                "Only selected users or no users are allowed to join devices to "
                "Microsoft Entra."
            )

        findings.append(report)
        return findings
