from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_image_not_publicly_shared(Check):
    """Ensure Compute Engine disk images are not publicly shared.

    This check evaluates whether custom disk images in GCP Compute Engine
    have IAM bindings that grant access to allAuthenticatedUsers, which allows
    anyone with a Google account to access the image.

    Note: allUsers cannot be assigned to Compute Engine images (API restriction).
    Only allAuthenticatedUsers can be set, which is the security risk.
    Reference: https://cloud.google.com/compute/docs/images/managing-access-custom-images

    - PASS: The disk image is not publicly shared.
    - FAIL: The disk image is publicly shared with allAuthenticatedUsers.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []
        for image in compute_client.images:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=image,
                location="global",
            )
            report.status = "PASS"
            report.status_extended = (
                f"Compute Engine disk image {image.name} is not publicly shared."
            )

            if image.publicly_shared:
                report.status = "FAIL"
                report.status_extended = f"Compute Engine disk image {image.name} is publicly shared with allAuthenticatedUsers."

            findings.append(report)

        return findings
