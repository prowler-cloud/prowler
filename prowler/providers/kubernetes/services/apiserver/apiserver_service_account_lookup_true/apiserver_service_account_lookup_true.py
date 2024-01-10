from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_service_account_lookup_true(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "Service account lookup is set to true in the API server."
            )

            service_account_lookup_set = False
            for container in pod.containers.values():
                # Check if "--service-account-lookup" is set to true
                if "--service-account-lookup=true" in container.command:
                    service_account_lookup_set = True
                    break

            if not service_account_lookup_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = "Service account lookup is not set to true in container {container.name}."

            findings.append(report)
        return findings
