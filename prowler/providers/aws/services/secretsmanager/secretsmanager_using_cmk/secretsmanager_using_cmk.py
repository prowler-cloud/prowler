from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import secretsmanager_client


class secretsmanager_using_cmk(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = secret.region
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.resource_tags = secret.tags

            # Check if the secret is using a customer managed key
            if secret.kms_key_id and "aws/secretsmanager" not in secret.kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SecretsManager secret {secret.name} is encrypted with a customer managed key {secret.kms_key_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SecretsManager secret {secret.name} is not encrypted with a customer managed key."
                )

            findings.append(report)

        return findings
