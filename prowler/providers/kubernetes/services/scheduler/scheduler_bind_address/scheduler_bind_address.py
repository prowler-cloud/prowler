from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.scheduler.scheduler_client import (
    scheduler_client,
)


class scheduler_bind_address(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in scheduler_client.scheduler_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = (
                f"Scheduler is not bound to the loopback address in pod {pod.name}."
            )
            for container in pod.containers.values():
                if "--bind-address=127.0.0.1" in str(container.command):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Scheduler is bound to the loopback address in pod {pod.name}."
                    )
            findings.append(report)
        return findings
