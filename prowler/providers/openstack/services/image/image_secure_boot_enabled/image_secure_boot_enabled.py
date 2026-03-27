"""OpenStack Image Secure Boot Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_secure_boot_enabled(Check):
    """Ensure images have Secure Boot set to required."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_secure_boot_enabled check.

        Iterates over all images and verifies that the os_secure_boot
        property is set to 'required', ensuring only signed bootloaders
        and firmware can execute.

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            if image.os_secure_boot == "required":
                report.status = "PASS"
                report.status_extended = (
                    f"Image {image.name} ({image.id}) has Secure Boot set to required."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Image {image.name} ({image.id}) does not have Secure Boot "
                    f"set to required (os_secure_boot={image.os_secure_boot})."
                )

            findings.append(report)

        return findings
