from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_admission_hostport_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} does not use HostPorts."

            for container in pod.containers.values():
                if container.ports and "host_port" in str(container.ports):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} uses HostPorts in container {container.name}."
                    )
                    break

            findings.append(report)

        return findings
