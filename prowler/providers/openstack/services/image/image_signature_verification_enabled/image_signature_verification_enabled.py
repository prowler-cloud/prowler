"""OpenStack Image Signature Verification Check."""

from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.image.image_client import image_client


class image_signature_verification_enabled(Check):
    """Ensure images have cryptographic signature verification properties set."""

    def execute(self) -> List[CheckReportOpenStack]:
        """Execute image_signature_verification_enabled check.

        Iterates over all images and verifies that all four signature
        properties are set: img_signature, img_signature_hash_method,
        img_signature_key_type, and img_signature_certificate_uuid.

        Returns:
            list[CheckReportOpenStack]: List of findings for each image.
        """
        findings: List[CheckReportOpenStack] = []

        for image in image_client.images:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=image)

            has_all_signatures = all(
                [
                    image.img_signature,
                    image.img_signature_hash_method,
                    image.img_signature_key_type,
                    image.img_signature_certificate_uuid,
                ]
            )

            if has_all_signatures:
                report.status = "PASS"
                report.status_extended = f"Image {image.name} ({image.id}) has all signature verification properties configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"Image {image.name} ({image.id}) does not have all signature verification properties configured."

            findings.append(report)

        return findings
