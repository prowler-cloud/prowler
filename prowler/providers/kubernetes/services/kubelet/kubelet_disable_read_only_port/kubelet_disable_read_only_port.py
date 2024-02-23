from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_disable_read_only_port(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            if "readOnlyPort" not in cm.kubelet_args:
                report.status = "MANUAL"
                report.status_extended = f"Kubelet does not have the argument `readOnlyPort` in config file {cm.name}, verify it in the node's cm.kubelet_args."
            else:
                if cm.kubelet_args.get("readOnlyPort") == 0:
                    report.status = "PASS"
                    report.status_extended = f"Kubelet has the read-only port disabled in config file {cm.name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Kubelet has the read-only port enabled in config file {cm.name}."
            findings.append(report)
        return findings
