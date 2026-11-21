from itertools import chain

from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_seccomp_profile_docker_default(Check):
    """Check that Pod containers are configured to use RuntimeDefault seccomp."""

    def execute(self) -> list[Check_Report_Kubernetes]:
        """Report the configured seccomp profile status for each Pod."""
        findings = []
        for pod in core_client.pods.values():
            if not pod.containers:
                continue

            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"All containers in Pod {pod.name} are configured to use "
                "the RuntimeDefault seccomp profile."
            )
            pod_profile = (pod.security_context or {}).get("seccomp_profile")
            containers = chain(
                pod.containers.values(),
                (pod.init_containers or {}).values(),
                (pod.ephemeral_containers or {}).values(),
            )
            for container in containers:
                profile = container.security_context.get("seccomp_profile")
                if profile is None:
                    profile = pod_profile

                profile_type = (profile or {}).get("type")
                if profile_type != "RuntimeDefault":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Container {container.name} in Pod {pod.name} has seccomp "
                        f"profile {profile_type or 'unset'}. RuntimeDefault is required."
                    )
                    break

            findings.append(report)

        return findings
