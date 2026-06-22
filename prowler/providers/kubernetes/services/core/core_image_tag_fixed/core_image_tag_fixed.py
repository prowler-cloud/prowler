from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


def _has_fixed_image_tag(image: str) -> bool:
    if "@" in image:
        return True

    image_name = image.rsplit("/", 1)[-1]
    if ":" not in image_name:
        return False

    tag = image_name.rsplit(":", 1)[-1]
    return bool(tag) and tag.lower() != "latest"


class core_image_tag_fixed(Check):
    """Ensure that image tag is not set to latest or blank."""

    def execute(self) -> list[Check_Report_Kubernetes]:
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

            for container in (pod.containers or {}).values():
                image = container.image
                if not _has_fixed_image_tag(image):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} has container {container.name} with image '{image}' that does not use a fixed tag."
                    break

            findings.append(report)

        return findings
