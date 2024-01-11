from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.scheduler.scheduler_client import (
    scheduler_client,
)


class scheduler_profiling(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in scheduler_client.scheduler_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = (
                f"Scheduler has profiling enabled in pod {pod.name}."
            )
            for container in pod.containers.values():
                if "--profiling=false" in str(container.command):
                    report.status = "PASS"
                    report.status_extended = (
                        f"Scheduler does not have profiling enabled in pod {pod.name}."
                    )
            findings.append(report)
        return findings
