from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_memory_requests_set(Check):
    """Ensure that memory requests are set on all containers."""

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
                f"Pod {pod.name} has memory requests set on all containers."
            )

            for container in pod.containers.values():
                if (
                    not container.resources
                    or not container.resources.get("requests")
                    or not container.resources["requests"].get("memory")
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} does not have memory requests set on container {container.name}."
                    break

            findings.append(report)

        return findings
