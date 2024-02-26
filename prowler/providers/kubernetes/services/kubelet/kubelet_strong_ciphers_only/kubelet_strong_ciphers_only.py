from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.kubelet.kubelet_client import kubelet_client


class kubelet_strong_ciphers_only(Check):
    def execute(self) -> Check_Report_Kubernetes:
        strong_ciphers = [
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_AES_128_GCM_SHA256",
        ]
        findings = []
        for cm in kubelet_client.kubelet_config_maps:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = cm.namespace
            report.resource_name = cm.name
            report.resource_id = cm.uid
            if "tlsCipherSuites" not in cm.kubelet_args:
                report.status = "MANUAL"
                report.status_extended = f"Kubelet does not have the argument `tlsCipherSuites` in config file {cm.name}, verify it in the node's arguments."
            else:
                if cm.kubelet_args["tlsCipherSuites"].issubset(strong_ciphers):
                    report.status = "PASS"
                    report.status_extended = f"Kubelet is configured with strong cryptographic ciphers in config file {cm.name}."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"Kubelet is not using only strong cryptographic ciphers in config file {cm.name}."
            findings.append(report)
        return findings
