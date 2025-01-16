from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_automatic_rotation_enabled(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=secret
            )
            if secret.rotation_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"SecretsManager secret {secret.name} has rotation enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SecretsManager secret {secret.name} has rotation disabled."
                )

            findings.append(report)

        return findings
