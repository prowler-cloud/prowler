import yaml

from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_authorization_mode(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            authorization = yaml.safe_load(cm.data["kubelet"])["authorization"]
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            report.status = "PASS"
            report.status_extended = f"Kubelet is not using 'AlwaysAllow' as the authorization mode in config file {cm.name}."
            if authorization["mode"] == "AlwaysAllow":
                report.status = "FAIL"
                report.status_extended = f"Kubelet is incorrectly set to use 'AlwaysAllow' as the authorization mode in config file {cm.name}."
            findings.append(report)
        return findings
