from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_kubelet_cert_auth(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "API Server has appropriate kubelet certificate authority configured."
            )
            for container in pod.containers.values():
                if "--kubelet-certificate-authority" not in container.command:
                    report.resource_id = container.name
                    report.status = "FAIL"
                    report.status_extended = f"API Server is missing kubelet certificate authority configuration in container {container.name}."
            findings.append(report)
        return findings
