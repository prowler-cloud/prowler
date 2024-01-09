from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_deny_service_external_ips(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "API Server has DenyServiceExternalIPs admission controller enabled."
            )
            for container in pod.containers.values():
                if (
                    "--disable-admission-plugins=DenyServiceExternalIPs"
                    in container.command
                ):
                    report.resource_id = container.name
                    report.status = "FAIL"
                    report.status_extended = f"API Server does not have DenyServiceExternalIPs enabled in container {container.name}."
            findings.append(report)
        return findings
