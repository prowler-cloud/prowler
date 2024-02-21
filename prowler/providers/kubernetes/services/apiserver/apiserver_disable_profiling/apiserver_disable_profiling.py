from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_disable_profiling(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Profiling is disabled in pod {pod.name}."
            profiling_enabled = False
            for container in pod.containers.values():
                profiling_enabled = False
                # Check if "--profiling" is set to false
                if "--profiling=false" not in str(container.command):
                    profiling_enabled = True
                    break
            if profiling_enabled:
                report.status = "FAIL"
                report.status_extended = f"Profiling is enabled in pod {pod.name}."

            findings.append(report)
        return findings
