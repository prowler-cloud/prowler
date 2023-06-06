from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.kms.kms_client import kms_client


class kms_key_rotation_enabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in kms_client.crypto_keys:
            report = Check_Report_GCP(self.metadata())
            report.project_id = key.project_id
            report.resource_id = key.name
            report.resource_name = key.name
            report.location = key.location
            report.status = "FAIL"
            report.status_extended = (
                f"Key {key.name} is not rotated every 90 days or less."
            )
            if key.rotation_period:
                if (
                    int(key.rotation_period[:-1]) // (24 * 3600) <= 90
                ):  # Convert seconds to days and check if less or equal than 90
                    report.status = "PASS"
                    report.status_extended = (
                        f"Key {key.name} is rotated every 90 days or less."
                    )
            findings.append(report)

        return findings
