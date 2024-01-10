from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_no_alwaysadmit_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = "AlwaysAdmit admission control plugin is not set."
            for container in pod.containers.values():
                if "--enable-admission-plugins" in container.command:
                    admission_plugins = container.command.split(
                        "--enable-admission-plugins="
                    )[1].split(",")
                    if "AlwaysAdmit" in admission_plugins:
                        report.resource_id = container.name
                        report.status = "FAIL"
                        report.status_extended = "AlwaysAdmit admission control plugin is set in container {container.name}."
            findings.append(report)
        return findings
