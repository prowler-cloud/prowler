from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.core.core_client import core_client


class apiserver_anonymous_requests(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in core_client.pods:
            if pod.namespace == "kube-system" and pod.name.startswith("kube-apiserver"):
                report = Check_Report_Kubernetes(self.metadata())
                report.namespace = pod.namespace
                report.resource_name = pod.name
                report.resource_id = pod.name
                report.status = "PASS"
                report.status_extended = "API Server does not anonymous-auth enabled."
                for container in pod.containers:
                    if "anonymous-auth=true" in container.command:
                        report.resource_id = container.name
                        report.status = "FAIL"
                        report.status_extended = f"API Server has anonymous-auth enabled in container {container.name}."
                findings.append(report)
        return findings
