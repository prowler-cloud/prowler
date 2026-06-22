from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_memory_requests_set(Check):
    """Ensure that memory requests are set on all containers."""

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
                f"Pod {pod.name} has memory requests set on all containers."
            )

            for container in (pod.containers or {}).values():
                resources = container.resources or {}
                requests = (
                    resources.get("requests") if isinstance(resources, dict) else None
                )
                memory = (
                    requests.get("memory")
                    if requests and isinstance(requests, dict)
                    else None
                )
                if not memory:
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} does not have memory requests set on container {container.name}."
                    break

            findings.append(report)

        return findings
