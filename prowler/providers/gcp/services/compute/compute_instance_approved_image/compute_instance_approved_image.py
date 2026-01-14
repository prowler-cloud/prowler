import re

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.compute.compute_client import compute_client


class compute_instance_approved_image(Check):
    """
    Ensure VM instances are launched from approved (golden) machine images.

    This check verifies that Compute Engine instances are using only approved
    machine images defined in the configuration. Using approved images ensures
    security best practices, consistency, and standardized deployments.

    - PASS: The VM instance is launched from an approved image.
    - FAIL: The VM instance is not launched from an approved image.
    - MANUAL: The VM instance is a GKE-managed node. GKE instances use Google-managed
      images and cannot be launched from custom golden images. Manual review recommended.
    """

    def execute(self) -> list[Check_Report_GCP]:
        findings = []

        approved_images = compute_client.audit_config.get("approved_vm_images", [])

        for instance in compute_client.instances:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=instance,
            )

            # GKE instances use Google-managed images and cannot be launched from custom golden images
            if instance.name.startswith("gke-"):
                report.status = "MANUAL"
                source_image = instance.source_image or "unknown"
                report.status_extended = (
                    f"VM Instance {instance.name} is a GKE-managed node using image source: {source_image}. "
                    f"GKE nodes use Google-managed images and cannot be launched from custom golden images. "
                    f"Manual review recommended to verify this aligns with your GKE security policies."
                )
                findings.append(report)
                continue

            source_image = instance.source_image or ""

            if not approved_images:
                report.status = "PASS"
                report.status_extended = (
                    f"VM Instance {instance.name} has no approved image list configured, "
                    f"skipping validation."
                )
            elif not source_image:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} has no source image information available."
            else:
                is_approved = False
                for pattern in approved_images:
                    if re.search(pattern, source_image, re.IGNORECASE):
                        is_approved = True
                        break

                if is_approved:
                    report.status = "PASS"
                    report.status_extended = f"VM Instance {instance.name} is launched from an approved image."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"VM Instance {instance.name} is not launched from an approved image. "
                        f"Source: {source_image}."
                    )

            findings.append(report)

        return findings
