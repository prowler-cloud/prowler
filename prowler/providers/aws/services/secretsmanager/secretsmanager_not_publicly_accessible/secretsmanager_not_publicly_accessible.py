from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.lib.policy import is_policy_public
from prowler.providers.aws.services.secretsmanager.secretsmanager_client import (
    secretsmanager_client,
)


class secretsmanager_not_publicly_accessible(Check):
    def execute(self):
        findings = []
        for secret in secretsmanager_client.secrets.values():
            if secret.policy is None:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=secret)
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
