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
                "NamespaceLifecycle admission control plugin is set."
            )

            namespace_lifecycle_plugin_set = False
            for container in pod.containers.values():
                # Check if "--enable-admission-plugins" includes "NamespaceLifecycle"
                # and "--disable-admission-plugins" does not include "NamespaceLifecycle"
                if "--enable-admission-plugins" in container.command:
                    admission_plugins = container.command.split(
                        "--enable-admission-plugins="
                    )[1].split(",")
                    if "NamespaceLifecycle" in admission_plugins:
                        namespace_lifecycle_plugin_set = True
                if "--disable-admission-plugins" in container.command:
                    disabled_plugins = container.command.split(
                        "--disable-admission-plugins="
                    )[1].split(",")
                    if "NamespaceLifecycle" in disabled_plugins:
                        namespace_lifecycle_plugin_set = False

            if not namespace_lifecycle_plugin_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = f"NamespaceLifecycle admission control plugin is not set in container {container.name}."

            findings.append(report)
        return findings
