from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_disable_anonymous_auth(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            authentication = cm.kubelet_args.get("authentication", {})
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            report.status = "FAIL"
            report.status_extended = (
                f"Kubelet has anonymous access enabled in config file {cm.name}."
            )
            if not authentication.get("anonymous", {}).get("enabled", False):
                report.status = "PASS"
                report.status_extended = f"Kubelet does not have anonymous access enabled in config file {cm.name}."
            findings.append(report)
        return findings
