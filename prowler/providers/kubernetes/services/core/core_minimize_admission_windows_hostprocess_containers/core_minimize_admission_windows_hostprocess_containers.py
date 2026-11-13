from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_minimize_admission_windows_hostprocess_containers(Check):
    def execute(self) -> list[Check_Report_Kubernetes]:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} does not have the ability to run a Windows HostProcess."
            )

            contexts = [("pod security context", pod.security_context)]
            for container_type, containers in (
                ("container", pod.containers),
                ("init container", pod.init_containers),
                ("ephemeral container", pod.ephemeral_containers),
            ):
                contexts.extend(
                    (f"{container_type} {container.name}", container.security_context)
                    for container in (containers or {}).values()
                )

            for location, security_context in contexts:
                windows_options = (security_context or {}).get("windows_options") or {}
                if windows_options.get("host_process") is True:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Pod {pod.name} has Windows HostProcess enabled in {location}."
                    )
                    break

            findings.append(report)

        return findings