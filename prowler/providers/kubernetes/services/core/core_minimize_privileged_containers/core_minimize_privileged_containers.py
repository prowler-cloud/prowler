from itertools import chain

from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_privileged_containers(Check):
    """Detect privileged containers in Kubernetes Pods."""

    def execute(self) -> list[Check_Report_Kubernetes]:
        """Report whether any container in each Pod enables privileged mode."""
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} does not contain a privileged container."
            )

            containers = chain(
                (pod.containers or {}).values(),
                (pod.init_containers or {}).values(),
                (pod.ephemeral_containers or {}).values(),
            )
            for container in containers:
                if container.security_context.get("privileged") is True:
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} contains a privileged container {container.name}."
                    break

            findings.append(report)

        return findings
