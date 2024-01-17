from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.etcd.etcd_client import etcd_client


class etcd_client_cert_auth(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in etcd_client.etcd_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = f"Etcd does not have client certificate authentication enabled in pod {pod.name}."
            for container in pod.containers.values():
                if "--client-cert-auth=true" in str(container.command):

                    report.status = "PASS"
                    report.status_extended = f"Etcd has client certificate authentication enabled in pod {pod.name}."
            findings.append(report)
        return findings
