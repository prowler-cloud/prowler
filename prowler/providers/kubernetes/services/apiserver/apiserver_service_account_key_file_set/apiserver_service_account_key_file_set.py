from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_service_account_key_file_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"Service account key file is set appropriately in pod {pod.name}."
            )

            service_account_key_file_set = False
            for container in pod.containers.values():
                # Check if "--service-account-key-file" is set
                if "--service-account-key-file" in str(container.command):
                    service_account_key_file_set = True
                    break

            if not service_account_key_file_set:
                report.status = "FAIL"
                report.status_extended = (
                    f"Service account key file is not set in pod {pod.name}."
                )

            findings.append(report)
        return findings
