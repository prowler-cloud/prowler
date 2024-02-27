from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)
from prowler.providers.kubernetes.services.etcd.etcd_client import etcd_client


class etcd_unique_ca(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        # Get first the CA Files of the apiserver pods
        apiserver_ca_files = []
        for pod in apiserver_client.apiserver_pods:
            for container in pod.containers.values():
                for command in container.command:
                    if command.startswith("--client-ca-file"):
                        apiserver_ca_files.append(command.split("=")[1])
        for pod in etcd_client.etcd_pods:
            etcd_ca_files = []
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "MANUAL"
            report.status_extended = f"Etcd uses a different CA file from the Kubernetes cluster CA in pod {pod.name}, but verify if the content is the same."
            for container in pod.containers.values():
                for command in container.command:
                    if command.startswith("--trusted-ca-file"):
                        etcd_ca_files.append(command.split("=")[1])
            if any(ca in etcd_ca_files for ca in apiserver_ca_files):
                report.status = "FAIL"
                report.status_extended = f"Etcd does not use a unique CA file, which could compromise its security in pod {pod.name}."
            findings.append(report)
        return findings
