from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_etcd_tls_config(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "TLS configuration for etcd is set appropriately in the API server."
            )
            etcd_tls_config_set = False
            for container in pod.containers.values():
                # Check if "--etcd-certfile" and "--etcd-keyfile" are set
                if (
                    "--etcd-certfile" in container.command
                    and "--etcd-keyfile" in container.command
                ):
                    etcd_tls_config_set = True
                    break

            if not etcd_tls_config_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = f"TLS configuration for etcd is not set in container {container.name}."

            findings.append(report)
        return findings
