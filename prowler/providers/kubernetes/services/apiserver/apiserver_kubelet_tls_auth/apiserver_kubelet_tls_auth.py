from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_kubelet_tls_auth(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"API Server has appropriate kubelet TLS authentication configured in pod {pod.name}."
            for container in pod.containers.values():
                if "--kubelet-client-certificate" not in str(
                    container.command
                ) and "--kubelet-client-key" not in str(container.command):

                    report.status = "FAIL"
                    report.status_extended = f"API Server is missing kubelet TLS authentication arguments in pod {pod.name}."
                    break
            findings.append(report)
        return findings
