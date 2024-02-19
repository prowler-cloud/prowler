from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_always_pull_images_plugin(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"AlwaysPullImages admission control plugin is set in pod {pod.name}."
            )
            plugin_set = False
            for container in pod.containers.values():
                plugin_set = False
                for command in container.command:
                    if command.startswith("--enable-admission-plugins"):
                        if "AlwaysPullImages" in command:
                            plugin_set = True
                if not plugin_set:
                    break
            if not plugin_set:
                report.status = "FAIL"
                report.status_extended = f"AlwaysPullImages admission control plugin is not set in pod {pod.name}."
            findings.append(report)
        return findings
