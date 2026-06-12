from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_cpu_requests_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} containers have CPU requests configured."
            )

            for container in pod.containers.values():
                resources = container.resources or {}
                requests = resources.get("requests") if isinstance(resources, dict) else None
                cpu = requests.get("cpu") if requests and isinstance(requests, dict) else None
                if not cpu:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} container {container.name} does not have a CPU request configured."
                    )
                    break

            findings.append(report)

        return findings

