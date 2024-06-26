from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_root_containers_admission(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} is not running as root user."

            for container in pod.containers.values():
                if (
                    container.security_context
                    and container.security_context.run_as_user == 0
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} is running as root user in container {container.name}."
                    break

            findings.append(report)

        return findings
