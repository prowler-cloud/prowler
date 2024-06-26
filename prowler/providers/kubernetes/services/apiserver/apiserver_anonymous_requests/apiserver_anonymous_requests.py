from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_anonymous_requests(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                f"API Server does not have anonymous-auth enabled in pod {pod.name}."
            )
            for container in pod.containers.values():
                if "--anonymous-auth=true" in container.command:

                    report.status = "FAIL"
                    report.status_extended = (
                        f"API Server has anonymous-auth enabled in pod {pod.name}."
                    )
            findings.append(report)
        return findings
