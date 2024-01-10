from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_event_rate_limit(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = "EventRateLimit admission control plugin is set."
            plugin_set = False
            for container in pod.containers.values():
                if "--enable-admission-plugins" in container.command:
                    admission_plugins = container.command.split(
                        "--enable-admission-plugins="
                    )[1].split(",")
                    if "EventRateLimit" not in admission_plugins:
                        plugin_set = True
                        break
            if not plugin_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = f"EventRateLimit admission control plugin is not set in container {container.name}."

            findings.append(report)
        return findings
