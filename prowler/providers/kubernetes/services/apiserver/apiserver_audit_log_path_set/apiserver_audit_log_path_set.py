from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_audit_log_path_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = "Audit log path is set in the API server."

            audit_log_path_set = False
            for container in pod.containers.values():
                # Check if "--audit-log-path" is set
                if "--audit-log-path" in container.command:
                    audit_log_path_set = True
                    break

            if not audit_log_path_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = (
                    "Audit log path is not set in container {container.name}."
                )

            findings.append(report)
        return findings
