from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_auth_mode_not_always_allow(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"API Server authorization mode is not set to AlwaysAllow in pod {pod.name}."
            for container in pod.containers.values():
                for command in container.command:
                    if command.startswith("--authorization-mode"):
                        if "AlwaysAllow" in (command.split("=")[1]):

                            report.status = "FAIL"
                            report.status_extended = f"API Server authorization mode is set to AlwaysAllow in pod {pod.name}."
            findings.append(report)
        return findings
