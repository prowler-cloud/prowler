from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_privileged_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            privileged_container = False
            for container in pod.containers.values():
                if "security_context" in container and container[
                    "security_context"
                ].get("privileged", False):
                    privileged_container = True
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = pod.namespace
                    report.resource_name = pod.name
                    report.resource_id = pod.uid
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} contains a privileged container {container.name}."
                    findings.append(report)
                    break
            if not privileged_container:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = (
                    f"Pod {pod.name} does not contain a privileged container."
                )
                findings.append(report)

        return findings
