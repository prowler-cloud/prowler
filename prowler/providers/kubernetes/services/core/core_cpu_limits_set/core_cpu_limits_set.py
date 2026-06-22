from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_cpu_limits_set(Check):
    """Check whether regular pod containers have CPU limits configured."""

    def execute(self) -> list[Check_Report_Kubernetes]:
        """Execute the Kubernetes pod CPU limits check.

        Returns:
            List of check reports for Kubernetes pods.
        """
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=pod)
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} regular containers have CPU limits configured."
            )

            for container in (pod.containers or {}).values():
                resources = container.resources or {}
                limits = (
                    resources.get("limits") if isinstance(resources, dict) else None
                )
                cpu = limits.get("cpu") if limits and isinstance(limits, dict) else None
                if not cpu:
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} container {container.name} does not have a CPU limit configured."
                    break

            findings.append(report)

        return findings
