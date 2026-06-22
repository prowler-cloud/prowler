from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.kms.kms_client import kms_client


class kms_key_rotation_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in kms_client.crypto_keys:
            report = Check_Report_GCP(metadata=self.metadata(), resource=key)
            if key.rotation_period:
                report.status = "PASS"
                report.status_extended = (
                    f"Key {key.name} has automatic rotation enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Key {key.name} does not have automatic rotation enabled."
                )
            findings.append(report)

        return findings
