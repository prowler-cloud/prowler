from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.controllermanager.controllermanager_client import (
    controllermanager_client,
)


class controllermanager_bind_address(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in controllermanager_client.controllermanager_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Controller Manager is bound to the loopback address in pod {pod.name}."
            for container in pod.containers.values():
                if "--bind-address=127.0.0.1" not in str(
                    container.command
                ) and "--address=127.0.0.1" not in str(container.command):
                    report.status = "FAIL"
                    report.status_extended = f"Controller Manager is not bound to the loopback address in pod {pod.name}."
                    break
            findings.append(report)
        return findings
