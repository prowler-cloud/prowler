from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class core_no_secrets_envs(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods.values():
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"Pod {pod.name} does not contain any secret environment variables."
            )

            for container in pod.containers.values():
                if "secretKeyRef" in str(container.env):
                    report.status = "FAIL"
                    report.status_extended = f"Pod {pod.name} contains secret environment variables in container {container.name}."
                    break

            findings.append(report)

        return findings
