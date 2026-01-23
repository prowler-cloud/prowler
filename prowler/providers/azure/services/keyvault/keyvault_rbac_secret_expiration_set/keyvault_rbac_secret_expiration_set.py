import time

from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.lib.logger import logger
from prowler.providers.azure.services.keyvault.keyvault_client import keyvault_client


class keyvault_rbac_secret_expiration_set(Check):
    def execute(self) -> Check_Report_Azure:
        start_time = time.perf_counter()
        findings = []
        total_secrets = 0

        for subscription, key_vaults in keyvault_client.key_vaults.items():
            for keyvault in key_vaults:
                if keyvault.properties.enable_rbac_authorization and keyvault.secrets:
                    for secret in keyvault.secrets:
                        total_secrets += 1
                        report = Check_Report_Azure(
                            metadata=self.metadata(), resource=secret
                        )
                        report.subscription = subscription
                        if not secret.attributes.expires and secret.enabled:
                            report.status = "FAIL"
                            report.status_extended = f"Secret '{secret.name}' in KeyVault '{keyvault.name}' does not have expiration date set."
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Secret '{secret.name}' in KeyVault '{keyvault.name}' has expiration date set."
                        findings.append(report)

        elapsed = time.perf_counter() - start_time
        logger.info(
            f"Check keyvault_rbac_secret_expiration_set: "
            f"processed {total_secrets} secrets, created {len(findings)} findings in {elapsed:.2f}s"
        )

        return findings
