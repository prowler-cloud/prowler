from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.etcd.etcd_client import etcd_client


class etcd_no_auto_tls(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in etcd_client.etcd_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Etcd is not configured to use self-signed certificates for TLS in pod {pod.name}."
            for container in pod.containers.values():
                if "--auto-tls=true" in str(container.command):
                    report.status = "FAIL"
                    report.status_extended = f"Etcd is configured to use self-signed certificates for TLS in pod {pod.name}."
                    break
            findings.append(report)
        return findings
