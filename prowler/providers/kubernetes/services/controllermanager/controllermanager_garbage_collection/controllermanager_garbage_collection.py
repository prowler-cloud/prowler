from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.controllermanager.controllermanager_client import (
    controllermanager_client,
)


class controllermanager_garbage_collection(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in controllermanager_client.controllermanager_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"Controller Manager has an appropriate garbage collection threshold in pod {pod.name}."
            for container in pod.containers.values():
                if "--terminated-pod-gc-threshold=12500" in str(container.command):
                    report.status = "FAIL"
                    report.status_extended = f"Controller Manager has the default garbage collection threshold in pod {pod.name}."
            findings.append(report)
        return findings
