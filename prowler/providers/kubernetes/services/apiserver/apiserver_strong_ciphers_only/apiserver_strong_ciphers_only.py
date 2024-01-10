from prowler.lib.check.models import Check, Check_Report_Kubernetes
from prowler.providers.kubernetes.services.apiserver.apiserver_client import (
    apiserver_client,
)


class apiserver_strong_ciphers_only(Check):
    def execute(self) -> Check_Report_Kubernetes:
        findings = []
        for pod in apiserver_client.apiserver_pods:
            report = Check_Report_Kubernetes(self.metadata())
            report.namespace = pod.namespace
            report.resource_name = pod.name
            report.resource_id = pod.uid
            report.status = "PASS"
            report.status_extended = f"API Server is configured with strong cryptographic ciphers in pod {pod.name}."
            strong_ciphers_set = True
            for container in pod.containers.values():
                # Check if strong ciphers are set in "--tls-cipher-suites"
                for command in container.command:
                    if command.startswith("--tls-cipher-suites"):
                        for cipher in command.split("=")[1].split(","):
                            if cipher not in [
                                "TLS_AES_128_GCM_SHA256",
                                "TLS_AES_256_GCM_SHA384",
                                "TLS_CHACHA20_POLY1305_SHA256",
                            ]:
                                strong_ciphers_set = False
                                break

            if not strong_ciphers_set:
                report.status = "FAIL"
                report.status_extended = f"API Server is not using only strong cryptographic ciphers in pod {pod.name}."

            findings.append(report)
        return findings
