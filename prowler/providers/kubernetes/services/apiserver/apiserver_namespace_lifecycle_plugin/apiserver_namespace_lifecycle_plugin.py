from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_namespace_lifecycle_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"NamespaceLifecycle admission control plugin is set in pod {pod.name}."
            )

            namespace_lifecycle_plugin_set = False
            for container in pod.containers.values():
                namespace_lifecycle_plugin_set = False
                # Check if "--enable-admission-plugins" includes "NamespaceLifecycle"
                # and "--disable-admission-plugins" does not include "NamespaceLifecycle"
                for command in container.command:
                    command = command.split("=")
                    flag = command[0]
                    value = command[1]

                    if (
                        flag == "--enable-admission-plugins"
                        and "NamespaceLifecycle" in value
                    ):
                        namespace_lifecycle_plugin_set = True
                    elif (
                        flag == "--disable-admission-plugins"
                        and "NamespaceLifecycle" in value
                    ):
                        namespace_lifecycle_plugin_set = False
                if not namespace_lifecycle_plugin_set:
                    break

            if not namespace_lifecycle_plugin_set:
                report.status = "FAIL"
                report.status_extended = f"NamespaceLifecycle admission control plugin is not set in pod {pod.name}."

            findings.append(report)
        return findings
