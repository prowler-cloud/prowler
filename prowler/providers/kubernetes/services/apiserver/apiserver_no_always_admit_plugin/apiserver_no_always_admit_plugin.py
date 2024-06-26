from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_no_always_admit_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"AlwaysAdmit admission control plugin is not set in pod {pod.name}."
            )
            always_admit_plugin = True
            for container in pod.containers.values():
                always_admit_plugin = True
                for command in container.command:
                    if command.startswith("--enable-admission-plugins"):
                        if "AlwaysAdmit" in (command.split("=")[1]):
                            report.status = "FAIL"
                            report.status_extended = f"AlwaysAdmit admission control plugin is set in pod {pod.name}."
                            always_admit_plugin = False
                            break
                if not always_admit_plugin:
                    break
            findings.append(report)
        return findings
