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
                f"TLS configuration for etcd is set appropriately in pod {pod.name}."
            )
            etcd_tls_config_set = True
            for container in pod.containers.values():
                # Check if "--etcd-certfile" and "--etcd-keyfile" are set
                if "--etcd-certfile" not in str(
                    container.command
                ) and "--etcd-keyfile" not in str(container.command):
                    etcd_tls_config_set = False
                    break

            if not etcd_tls_config_set:
                report.status = "FAIL"
                report.status_extended = (
                    f"TLS configuration for etcd is not set in pod {pod.name}."
                )

            findings.append(report)
        return findings
