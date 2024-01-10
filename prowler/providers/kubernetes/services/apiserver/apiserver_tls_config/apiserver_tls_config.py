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
                "TLS certificate and key are set appropriately in the API server."
            )
            tls_config_set = False
            for container in pod.containers.values():
                # Check if both "--tls-cert-file" and "--tls-private-key-file" are set
                if (
                    "--tls-cert-file" in container.command
                    and "--tls-private-key-file" in container.command
                ):
                    tls_config_set = True
                    break

            if not tls_config_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = "TLS certificate and/or key are not set in container {container.name}."

            findings.append(report)
        return findings
