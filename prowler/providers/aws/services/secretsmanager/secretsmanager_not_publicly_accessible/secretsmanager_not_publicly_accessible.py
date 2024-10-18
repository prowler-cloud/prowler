from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            report = Check_Report_AWS(self.metadata())
            report.region = secret.region
            report.resource_id = secret.name
            report.resource_arn = secret.arn
            report.resource_tags = secret.tags
            report.status = "PASS"
            report.status_extended = (
                f"SecretsManager secret {secret.name} is not publicly accessible."
            )
            if is_policy_public(
                secret.policy,
                secretsmanager_client.audited_account,
            ):
                report.status = "FAIL"
                report.status_extended = f"SecretsManager secret {secret.name} is publicly accessible due to its resource policy."

            findings.append(report)

        return findings
