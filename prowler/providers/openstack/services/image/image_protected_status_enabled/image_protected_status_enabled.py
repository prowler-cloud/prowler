"""OpenStack Image Protected Status Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_protected_status_enabled(Check):
    """Ensure images have deletion protection enabled."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_protected_status_enabled check.

        Iterates over all images and verifies that the protected flag is
        set to True, preventing accidental or malicious deletion.

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            if image.protected:
                report.status = "PASS"
                report.status_extended = (
                    f"Image {image.name} ({image.id}) has deletion protection enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Image {image.name} ({image.id}) does not have deletion protection enabled."

            findings.append(report)

        return findings
