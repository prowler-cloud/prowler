from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_readonly_root_filesystem_enabled(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} has read-only root filesystem enabled for all containers."

            for container in pod.containers.values():
                if (
                    container.security_context.get("read_only_root_filesystem")
                    is not True
                ):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} container {container.name} does not have readOnlyRootFilesystem set to true."
                    break

            findings.append(report)

        return findings
