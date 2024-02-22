from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.controllermanager.controllermanager_client import (
    controllermanager_client,
)


class controllermanager_service_account_private_key_file(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in controllermanager_client.controllermanager_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Controller Manager does not have the service account private key file set in pod {pod.name}."
            for container in pod.containers.values():
                if "--service-account-private-key-file=" not in str(container.command):
                    report.status = "FAIL"
                    report.status_extended = f"Controller Manager has the service account private key file set in pod {pod.name}."
                    break
            findings.append(report)
        return findings
