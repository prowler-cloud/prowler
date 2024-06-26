from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_hostNetwork_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            if pod.host_network:
                report.status = "FAIL"
                report.status_extended = f"Pod {pod.name} is using hostNetwork."
            else:
                report.status = "PASS"
                report.status_extended = f"Pod {pod.name} is not using hostNetwork."
            findings.append(report)

        return findings
