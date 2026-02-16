"""OpenStack Image Memory Encryption Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_encryption_enabled(Check):
    """Ensure images have hardware memory encryption enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_encryption_enabled check.

        Iterates over all images and verifies that the hw_mem_encryption
        property is set to True, enabling AMD SEV guest memory encryption.

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            if image.hw_mem_encryption is True:
                report.status = "PASS"
                report.status_extended = f"Image {image.name} ({image.id}) has hardware memory encryption enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Image {image.name} ({image.id}) does not have hardware memory encryption enabled."

            findings.append(report)

        return findings
