from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_audit_log_maxsize_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "Audit log max size is set appropriately in the API server."
            )

            audit_log_maxsize_set = False
            for container in pod.containers.values():
                # Check if "--audit-log-maxsize" is set to 100 MB or as appropriate
                if "--audit-log-maxsize" in container.command:
                    maxsize_value = int(
                        container.command.split("--audit-log-maxsize=")[1].split(" ")[0]
                    )
                    if maxsize_value >= 100:
                        audit_log_maxsize_set = True
                        break

            if not audit_log_maxsize_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = f"Audit log max size is not set to 100 MB or as appropriate in container {container.name}."

            findings.append(report)
        return findings
