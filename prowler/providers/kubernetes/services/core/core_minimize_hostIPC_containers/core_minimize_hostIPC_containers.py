from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_hostIPC_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            if pod.host_ipc:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "FAIL"
                report.status_extended = f"Pod {pod.name} is using hostIPC."
                findings.append(report)
            else:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = f"Pod {pod.name} is not using hostIPC."
                findings.append(report)

        return findings
