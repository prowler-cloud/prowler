from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.etcd.etcd_client import etcd_client


class etcd_peer_tls_config(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in etcd_client.etcd_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = f"Etcd does not have TLS configured for peer connections in pod {pod.name}."
            for container in pod.containers.values():
                if "--peer-cert-file" in str(
                    container.command
                ) and "--peer-key-file" in str(container.command):

                    report.status = "PASS"
                    report.status_extended = f"Etcd is configured with TLS for peer connections in pod {pod.name}."
            findings.append(report)
        return findings
