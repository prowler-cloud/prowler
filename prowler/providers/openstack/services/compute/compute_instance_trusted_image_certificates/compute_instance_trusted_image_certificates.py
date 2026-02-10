from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.compute.compute_client import compute_client


class compute_instance_trusted_image_certificates(Check):
    """Ensure compute instances use trusted image certificates for image signature validation."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for instance in compute_client.instances:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=instance)
            if (
                instance.trusted_image_certificates
                and len(instance.trusted_image_certificates) > 0
            ):
                report.status = "PASS"
                cert_ids = ", ".join(instance.trusted_image_certificates)
                report.status_extended = f"Instance {instance.name} ({instance.id}) uses trusted image certificates: {cert_ids}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Instance {instance.name} ({instance.id}) does not use trusted image certificates (image signature validation not enforced)."

            findings.append(report)

        return findings
