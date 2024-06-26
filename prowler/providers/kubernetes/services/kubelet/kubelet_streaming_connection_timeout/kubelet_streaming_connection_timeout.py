from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_streaming_connection_timeout(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            if "streamingConnectionIdleTimeout" not in cm.kubelet_args:
                report.status = "MANUAL"
                report.status_extended = f"Kubelet does not have the argument `streamingConnectionIdleTimeout` in config file {cm.name}, verify it in the node's arguments."
            else:
                if cm.kubelet_args["streamingConnectionIdleTimeout"] != 0:
                    report.status = "PASS"
                    report.status_extended = f"Kubelet is configured with a non-zero streaming connection idle timeout in config file {cm.name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Kubelet has a streaming connection idle timeout set to 0 in config file {cm.name}."
            findings.append(report)
        return findings
