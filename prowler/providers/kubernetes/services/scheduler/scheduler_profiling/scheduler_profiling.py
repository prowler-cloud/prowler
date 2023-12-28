from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.scheduler.scheduler_client import (
    scheduler_client,
)


class scheduler_profiling(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        pod = scheduler_client.scheduler_pod
        report = Check_Report_Kubernetes(self.metadata())
        report.namespace = pod.namespace
        report.resource_name = pod.name
        report.resource_id = pod.uid
        report.status = "PASS"
        report.status_extended = "Scheduler does not have profiling enabled."
        for container in pod.containers.values():
            if "--profiling=true" in container.command:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = (
                    f"Scheduler has profiling enabled in container {container.name}."
                )
        findings.append(report)
        return findings
