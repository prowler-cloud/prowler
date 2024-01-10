from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_encryption_provider_config_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "Encryption provider config is set appropriately in the API server."
            )

            encryption_provider_config_set = False
            for container in pod.containers.values():
                # Check if "--encryption-provider-config" is set
                if "--encryption-provider-config" in container.command:
                    encryption_provider_config_set = True
                    break

            if not encryption_provider_config_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = f"Encryption provider config is not set in container {container.name}."

            findings.append(report)
        return findings
