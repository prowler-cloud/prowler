from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_node_restriction_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"NodeRestriction admission control plugin is set in pod {pod.name}."
            )
            node_restriction_plugin_set = False
            for container in pod.containers.values():
                # Check if "--enable-admission-plugins" includes "NodeRestriction"
                for command in container.command:
                    if command.startswith("--enable-admission-plugins"):
                        if "NodeRestriction" in (command.split("=")[1]):
                            node_restriction_plugin_set = True

            if not node_restriction_plugin_set:
                report.status = "FAIL"
                report.status_extended = f"NodeRestriction admission control plugin is not set in pod {pod.name}."

            findings.append(report)
        return findings
