from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.secretmanager.secretmanager_client import (
    secretmanager_client,
)


class secretmanager_secret_not_publicly_accessible(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for secret in secretmanager_client.secrets:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=secret,
                resource_id=secret.name,
                location=secret.location,
            )
            if secret.publicly_accessible:
                report.status = "FAIL"
                report.status_extended = (
                    f"Secret {secret.name} is publicly accessible via "
                    f"'allUsers' or 'allAuthenticatedUsers' IAM binding."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Secret {secret.name} is not publicly accessible."
                )
            findings.append(report)
        return findings
