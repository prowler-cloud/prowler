from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_client_ca_file_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Client CA file is set appropriately in the API server in pod {pod.name}."
            client_ca_file_set = False
            for container in pod.containers.values():
                client_ca_file_set = False
                # Check if "--client-ca-file" is set
                if "--client-ca-file" in str(container.command):
                    client_ca_file_set = True
                if not client_ca_file_set:
                    break

            if not client_ca_file_set:
                report.status = "FAIL"
                report.status_extended = f"Client CA file is not set in pod {pod.name}."

            findings.append(report)
        return findings
