from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_no_token_auth_file(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = "API Server does not have token-auth-file enabled."
            for container in pod.containers.values():
                if "--token-auth-file" in container.command:
                    report.resource_id = container.name
                    report.status = "FAIL"
                    report.status_extended = f"API Server has token-auth-file enabled in container {container.name}."
            findings.append(report)
        return findings
