from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_admission_windows_hostprocess_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            windows_host_process = False
            for container in pod.containers.values():
                if (
                    "security_context" in container
                    and container.security_context.windows_options
                    and container.security_context.windows_options.host_process
                ):
                    windows_host_process = True
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = pod.namespace
                    report.resource_name = pod.name
                    report.resource_id = pod.uid
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} contains a Windows HostProcess in container {container.name}."
                    findings.append(report)
                    break
            if not windows_host_process:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = (
                    f"Pod {pod.name} does not contain a Windows HostProcess."
                )
                findings.append(report)

        return findings
