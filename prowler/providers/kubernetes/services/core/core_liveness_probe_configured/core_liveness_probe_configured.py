from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_liveness_probe_configured(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} has liveness probes configured for all containers."
            )

            for container in pod.containers.values():
                if not container.liveness_probe:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} container {container.name} does not have a liveness probe configured."
                    )
                    break

            findings.append(report)

        return findings

