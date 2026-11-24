from itertools import chain

from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_allowPrivilegeEscalation_containers(Check):
    """Check that Pod containers explicitly disable privilege escalation."""

    def execute(self) -> list[Check_Report_Kubernetes]:
        """Report whether each applicable Pod meets the container setting."""
        findings = []
        for pod in core_client.pods.values():
            if pod.os_name == "windows":
                continue

            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} sets allowPrivilegeEscalation to false for all containers."

            containers = chain(
                (pod.containers or {}).values(),
                (pod.init_containers or {}).values(),
                (pod.ephemeral_containers or {}).values(),
            )
            for container in containers:
                # An omitted setting defaults to true in Kubernetes.
                if (
                    container.security_context.get("allow_privilege_escalation")
                    is not False
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} must set allowPrivilegeEscalation to false in container {container.name}."
                    break

            findings.append(report)

        return findings
