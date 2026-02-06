from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


def _has_fixed_image(image: str) -> bool:
    if not image:
        return False
    # If image referenced by digest, consider fixed
    if "@" in image:
        return True
    # Split the path portion and check for tag after last '/'
    last_part = image.split("/")[-1]
    if ":" not in last_part:
        return False
    tag = last_part.split(":", 1)[1]
    if not tag:
        return False
    return tag.lower() != "latest"


class core_image_tag_fixed(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} containers use fixed image tags."

            for container in pod.containers.values():
                if not _has_fixed_image(container.image):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} container {container.name} uses an unfixed image tag: {container.image}."
                    )
                    break

            findings.append(report)

        return findings

