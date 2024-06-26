from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_tls_cert_and_key(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            if (
                "tlsCertFile" not in cm.kubelet_args
                or "tlsPrivateKeyFile" not in cm.kubelet_args
            ):
                report.status = "FAIL"
                report.status_extended = f"Kubelet is missing TLS certificate and/or private key configuration in config file {cm.name}."
            else:
                report.status = "PASS"
                report.status_extended = f"Kubelet has appropriate TLS certificate and private key configured in config file {cm.name}."
            findings.append(report)
        return findings
