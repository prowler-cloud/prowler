from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.etcd.etcd_client import etcd_client


class etcd_tls_encryption(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in etcd_client.etcd_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = "Etcd does not have TLS encryption configured."
            for container in pod.containers.values():
                if (
                    "--cert-file" in container.command
                    and "--key-file" in container.command
                ):
                    report.resource_id = container.name
                    report.status = "PASS"
                    report.status_extended = "Etcd has configured TLS encryption."
            findings.append(report)
        return findings
