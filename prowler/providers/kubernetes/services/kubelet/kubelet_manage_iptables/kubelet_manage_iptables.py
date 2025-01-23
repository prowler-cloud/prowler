from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_manage_iptables(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            report = Check_Report_Kubernetes(metadata=self.metadata(), resource=cm)
            if "makeIPTablesUtilChains" not in cm.kubelet_args:
                report.status = "MANUAL"
                report.status_extended = f"Kubelet does not have the argument `makeIPTablesUtilChains` in config file {cm.name}, verify it in the node's arguments."
            else:
                if cm.kubelet_args["makeIPTablesUtilChains"]:
                    report.status = "PASS"
                    report.status_extended = f"Kubelet is configured to manage iptables in config file {cm.name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Kubelet is not configured to manage iptables in config file {cm.name}."
            findings.append(report)
        return findings
