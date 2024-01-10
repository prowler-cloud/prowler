from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_etcd_cafile_set(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = (
                "etcd CA file is set appropriately in the API server."
            )
            etcd_cafile_set = False
            for container in pod.containers.values():
                # Check if "--etcd-cafile" is set
                if "--etcd-cafile" in container.command:
                    etcd_cafile_set = True
                    break

            if not etcd_cafile_set:
                report.resource_id = container.name
                report.status = "FAIL"
                report.status_extended = (
                    f"etcd CA file is not set in container {container.name}."
                )

            findings.append(report)
        return findings
