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
            report.status_extended = f"API Server has DenyServiceExternalIPs admission controller enabled in pod {pod.name}."
            deny_service_external_ips = False
            for container in pod.containers.values():
                deny_service_external_ips = False
                for command in container.command:
                    if command.startswith("--disable-admission-plugins"):
                        if "DenyServiceExternalIPs" in (command.split("=")[1]):
                            deny_service_external_ips = True
                if not deny_service_external_ips:
                    break
            if not deny_service_external_ips:
                report.status = "FAIL"
                report.status_extended = f"API Server does not have DenyServiceExternalIPs enabled in pod {pod.name}."
            findings.append(report)
        return findings
