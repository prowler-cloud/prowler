from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_service_account_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"ServiceAccount admission control plugin is set in pod {pod.name}."
            )

            service_account_plugin_set = False
            for container in pod.containers.values():
                service_account_plugin_set = False
                # Check if "--enable-admission-plugins" includes "ServiceAccount"
                # and "--disable-admission-plugins" does not include "ServiceAccount"
                for command in container.command:
                    if command.startswith("--enable-admission-plugins"):
                        if "ServiceAccount" in (command.split("=")[1]):
                            service_account_plugin_set = True
                    elif command.startswith("--disable-admission-plugins"):
                        if "ServiceAccount" in (command.split("=")[1]):
                            service_account_plugin_set = False
                if not service_account_plugin_set:
                    break

            if not service_account_plugin_set:
                report.status = "FAIL"
                report.status_extended = f"ServiceAccount admission control plugin is not set in pod {pod.name}."

            findings.append(report)
        return findings
