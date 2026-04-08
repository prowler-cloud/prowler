"""OpenStack Image Sharing Scope Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_not_shared_with_multiple_projects(Check):
    """Ensure images are not shared with an excessive number of projects."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_not_shared_with_multiple_projects check.

        Iterates over all images and verifies that shared images do not
        exceed the accepted member threshold (default 5, configurable via
        audit_config 'image_sharing_threshold').

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []
        threshold = image_client.audit_config.get("image_sharing_threshold", 5)

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            if image.visibility != "shared":
                report.status = "PASS"
                report.status_extended = f"Image {image.name} ({image.id}) is not shared (visibility={image.visibility})."
            else:
                accepted_count = sum(1 for m in image.members if m.status == "accepted")

                if accepted_count > threshold:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Image {image.name} ({image.id}) is shared with "
                        f"{accepted_count} accepted projects, exceeding the "
                        f"threshold of {threshold}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Image {image.name} ({image.id}) is shared with "
                        f"{accepted_count} accepted projects, within the "
                        f"threshold of {threshold}."
                    )

            findings.append(report)

        return findings
