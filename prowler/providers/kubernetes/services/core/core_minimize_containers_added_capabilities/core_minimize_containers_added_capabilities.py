from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_containers_added_capabilities(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Pod {pod.name} does not have added capabilities."

            for container in pod.containers.values():
                if "security_context" in container and container[
                    "security_context"
                ].get("capabilities"):
                    if container.security_context.capabilities.add:
                        report.status = "FAIL"
                        report.status_extended = f"Pod {pod.name} has added capabilities in container {container.name}."
                        break

            findings.append(report)

        return findings
