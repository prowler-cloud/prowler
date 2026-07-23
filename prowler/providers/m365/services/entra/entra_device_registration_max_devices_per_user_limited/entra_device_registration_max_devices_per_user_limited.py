from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# CIS recommends a maximum of 10 devices per user (or less).
MAX_DEVICES_PER_USER = 10


class entra_device_registration_max_devices_per_user_limited(Check):
    """Check if the maximum number of devices per user is limited.

    The device registration policy should set the maximum number of Entra joined or
    registered devices per user to 10 or less.

    - PASS: The maximum number of devices per user is 10 or less.
    - FAIL: The maximum number of devices per user is greater than 10 (or unlimited).
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
        quota = policy.user_device_quota
        report.status = "FAIL"
        report.status_extended = (
            f"The maximum number of devices per user is {quota}, which exceeds the "
            f"recommended limit of {MAX_DEVICES_PER_USER}."
        )

        if quota is not None and quota <= MAX_DEVICES_PER_USER:
            report.status = "PASS"
            report.status_extended = (
                f"The maximum number of devices per user is {quota}, within the "
                f"recommended limit of {MAX_DEVICES_PER_USER}."
            )

        findings.append(report)
        return findings
