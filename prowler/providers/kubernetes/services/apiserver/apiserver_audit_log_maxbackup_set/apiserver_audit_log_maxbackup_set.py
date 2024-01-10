from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_audit_log_maxbackup_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Audit log max backup is set appropriately in the API server in pod {pod.name}."
            audit_log_maxbackup_set = False
            for container in pod.containers.values():
                # Check if "--audit-log-maxbackup" is set to 10 or as appropriate
                for command in container.command:
                    if command.startswith("--audit-log-maxbackup"):
                        if int(command.split("=")[1]) >= 10:
                            audit_log_maxbackup_set = True
                            break

            if not audit_log_maxbackup_set:
                report.status = "FAIL"
                report.status_extended = f"Audit log max backup is not set to 10 or as appropriate in pod {pod.name}."

            findings.append(report)
        return findings
