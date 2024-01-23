from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_allowPrivilegeEscalation_containers(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            privileged_container = False
            for container in pod.containers.values():
                if "security_context" in container and container[
                    "security_context"
                ].get("allow_privilege_escalation", False):
                    privileged_container = True
                    report = Check_Report_Kubernetes(self.metadata())
                    report.namespace = pod.namespace
                    report.resource_name = pod.name
                    report.resource_id = pod.uid
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} allows privilege escalation in container {container.name}."
                    findings.append(report)
                    break
            if not privileged_container:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = (
                    f"Pod {pod.name} does not allow privilege escalation."
                )
                findings.append(report)

        return findings
