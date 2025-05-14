from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.kms.kms_client import kms_client


class kms_key_not_publicly_accessible(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in kms_client.crypto_keys:
            report = Check_Report_GCP(metadata=self.metadata(), resource=key)
            report.status = "PASS"
            report.status_extended = f"Key {key.name} is not exposed to Public."
            for member in key.members:
                if member == "allUsers" or member == "allAuthenticatedUsers":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Key {key.name} may be publicly accessible."
                    )
            findings.append(report)

        return findings
