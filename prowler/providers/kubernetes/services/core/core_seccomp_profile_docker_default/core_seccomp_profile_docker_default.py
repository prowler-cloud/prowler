from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_seccomp_profile_docker_default(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid

            pod_seccomp_correct = (
                pod.security_context
                and pod.security_context.seccomp_profile
                and pod.security_context.seccomp_profile.type == "RuntimeDefault"
            )
            containers_seccomp_correct = True

            # Check container-level seccomp profile
            for container in pod.containers.values():
                if not (
                    container.security_context
                    and container.security_context.seccomp_profile
                    and container.security_context.seccomp_profile.type
                    == "RuntimeDefault"
                ):
                    containers_seccomp_correct = False
                    break

            # Determine the report status
            if pod_seccomp_correct or containers_seccomp_correct:
                report.status = "PASS"
                report.status_extended = f"Pod {pod.name} and its containers have docker/default seccomp profile enabled."
            else:
                report.status = "FAIL"
                if not pod_seccomp_correct and not containers_seccomp_correct:
                    report.status_extended = f"Pod {pod.name} does not have docker/default seccomp profile enabled at both pod and container levels."
                elif not pod_seccomp_correct:
                    report.status_extended = f"Pod {pod.name} does not have docker/default seccomp profile enabled at pod level."
                else:
                    report.status_extended = f"Pod {pod.name} does not have docker/default seccomp profile enabled at container level."

            findings.append(report)

        return findings
