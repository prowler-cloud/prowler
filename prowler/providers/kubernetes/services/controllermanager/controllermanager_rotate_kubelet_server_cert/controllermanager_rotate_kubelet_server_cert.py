from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.controllermanager.controllermanager_client import (
    controllermanager_client,
)


class controllermanager_rotate_kubelet_server_cert(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in controllermanager_client.controllermanager_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "FAIL"
            report.status_extended = f"Controller Manager does not have RotateKubeletServerCertificate set to true in pod {pod.name}."
            for container in pod.containers.values():
                for command in container.command:
                    if command.startswith("--feature-gates"):
                        if "RotateKubeletServerCertificate=true" in (
                            command.split("=")[1]
                        ):
                            report.status = "PASS"
                            report.status_extended = f"Controller Manager has RotateKubeletServerCertificate set to true in pod {pod.name}."
            findings.append(report)
        return findings
