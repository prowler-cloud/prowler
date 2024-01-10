from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_audit_log_maxage_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "Audit log max age is set appropriately in the API server."
            )

            audit_log_maxage_set = False
            for container in pod.containers.values():
                # Check if "--audit-log-maxage" is set to 30 or as appropriate
                if "--audit-log-maxage" in container.command:
                    maxage_value = int(
                        container.command.split("--audit-log-maxage=")[1].split(" ")[0]
                    )
                    if maxage_value >= 30:
                        audit_log_maxage_set = True
                        break

            if not audit_log_maxage_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = "Audit log max age is not set to 30 or as appropriate in container {container.name}."

            findings.append(report)
        return findings
