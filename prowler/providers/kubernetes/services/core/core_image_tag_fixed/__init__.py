from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_image_tag_fixed(Check):
    """Ensure that image tag is not set to Latest or Blank."""

    def execute(self) -> Check_Report_Kubernetes:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} has fixed image tags on all containers."
            )

            for container in pod.containers.values():
                image = container.image
                # No tag means implicit "latest"; explicit ":latest" is also non-compliant
                if ":" not in image or image.endswith(":latest"):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} has container {container.name} with image '{image}' that does not use a fixed tag."
                    break

            findings.append(report)

        return findings
