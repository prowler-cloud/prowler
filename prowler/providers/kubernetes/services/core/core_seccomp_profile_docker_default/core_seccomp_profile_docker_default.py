from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_seccomp_profile_docker_default(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            if (
                pod.security_context
                and pod.security_context.seccomp_profile
                and pod.security_context.seccomp_profile.type == "RuntimeDefault"
            ):
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "PASS"
                report.status_extended = (
                    f"Pod {pod.name} has docker/default seccomp profile enabled."
                )
                findings.append(report)
            else:
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.uid
                report.status = "FAIL"
                report.status_extended = f"Pod {pod.name} does not have docker/default seccomp profile enabled."
                findings.append(report)

        return findings
