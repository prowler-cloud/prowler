from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.secretmanager.secretmanager_client import (
    secretmanager_client,
)


class secretmanager_secret_not_publicly_accessible(Check):
    """Check that Secret Manager secrets do not grant access to all users.

    Verifies that no Secret Manager secret has an IAM binding granting access
    to `allUsers` or `allAuthenticatedUsers`.
    """

    def execute(self) -> list[Check_Report_GCP]:
        """Execute the public-access check across all Secret Manager secrets.

        Returns:
            A list of `Check_Report_GCP` findings, one per secret. Status is
            `FAIL` when the secret is accessible to `allUsers` or
            `allAuthenticatedUsers` and `PASS` otherwise.
        """
        findings = []
        for secret in secretmanager_client.secrets:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=secret,
                resource_id=secret.name,
            )
            if secret.publicly_accessible:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} is publicly accessible "
                    f"(allUsers or allAuthenticatedUsers IAM binding detected)."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Secret {secret.name} is not publicly accessible."
                )
            findings.append(report)
        return findings
