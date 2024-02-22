from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_tls_config(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"TLS certificate and key are set appropriately in pod {pod.name}."
            )
            for container in pod.containers.values():
                # Check if both "--tls-cert-file" and "--tls-private-key-file" are set
                if "--tls-cert-file" not in str(
                    container.command
                ) or "--tls-private-key-file" not in str(container.command):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"TLS certificate and/or key are not set in pod {pod.name}."
                    )
                    break

            findings.append(report)
        return findings
