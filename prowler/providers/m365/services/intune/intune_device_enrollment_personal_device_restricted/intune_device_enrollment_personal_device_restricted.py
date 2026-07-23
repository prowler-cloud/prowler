from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.intune.intune_client import intune_client


class intune_device_enrollment_personal_device_restricted(Check):
    """Check if the default device enrollment restriction blocks personal devices.

    The default (priority 0) device platform restriction configuration should block
    personally owned devices for all platforms
    (``personalDeviceEnrollmentBlocked`` set to true).

    - PASS: The default platform restriction blocks personal devices for all
      platforms.
    - FAIL: The default platform restriction allows personal devices for one or more
      platforms.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        configurations = intune_client.device_enrollment_configurations

        default_config = next(
            (config for config in configurations if config.priority == 0),
            None,
        )
        if not default_config:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=default_config,
            resource_name="Default Device Enrollment Platform Restrictions",
            resource_id=default_config.id,
        )

        restrictions = default_config.platform_restrictions
        if restrictions and all(restrictions.values()):
            report.status = "PASS"
            report.status_extended = (
                "The default device enrollment restriction blocks personally owned "
                "devices for all platforms."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "The default device enrollment restriction allows personally owned "
                "devices for one or more platforms."
            )

        findings.append(report)
        return findings
