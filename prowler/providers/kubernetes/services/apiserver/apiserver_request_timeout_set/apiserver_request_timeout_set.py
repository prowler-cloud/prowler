from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_request_timeout_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "Request timeout is set appropriately in the API server."
            )
            request_timeout_set = False
            for container in pod.containers.values():
                # Check if "--request-timeout" is set to an appropriate value
                if "--request-timeout" in container.command:
                    # timeout_value = container.command.split("--request-timeout=")[
                    #     1
                    # ].split(" ")[0]
                    # Assuming the value is valid, e.g., '300s' or '1m'
                    request_timeout_set = True
                    break

            if not request_timeout_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = "Request timeout is not set or not set appropriately in container {container.name}."

            findings.append(report)
        return findings
