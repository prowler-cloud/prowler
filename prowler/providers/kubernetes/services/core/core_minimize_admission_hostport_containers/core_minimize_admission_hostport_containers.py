from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_admission_hostport_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            hosts_ports = False
            for container in pod.containers.values():
                if any(port.host_port for port in container.ports):
                    hosts_ports = True
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = pod.namespace
                    report.resource_name = pod.name
                    report.resource_id = pod.uid
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} uses HostPorts in container {container.name}."
                    )
                    findings.append(report)
                    break
            if not hosts_ports:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = f"Pod {pod.name} does not use HostPorts."
                findings.append(report)

        return findings
