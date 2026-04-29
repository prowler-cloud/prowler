"""OpenStack Image Public Visibility Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_not_publicly_visible(Check):
    """Ensure images are not publicly visible to all tenants."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_not_publicly_visible check.

        Iterates over all images and verifies that visibility is not set to
        'public', which would expose the image to all tenants.

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            if image.visibility == "public":
                report.status = "FAIL"
                report.status_extended = f"Image {image.name} ({image.id}) is publicly visible to all tenants."
            else:
                report.status = "PASS"
                report.status_extended = f"Image {image.name} ({image.id}) is not publicly visible (visibility={image.visibility})."

            findings.append(report)

        return findings
