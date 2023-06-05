from datetime import datetime, timezone

from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.apikeys.apikeys_client import apikeys_client


class apikeys_key_rotated_in_90_days(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in apikeys_client.keys:
            report = Check_Report_GCP(self.metadata())
            report.project_id = apikeys_client.project_id
            report.resource_id = key.id
            report.resource_name = key.name
            report.status = "PASS"
            report.status_extended = f"API key {key.name} created in less than 90 days."
            if (
                datetime.now(timezone.utc)
                - datetime.strptime(key.creation_time, "%Y-%m-%dT%H:%M:%S.%f%z")
            ).days > 90:
                report.status = "FAIL"
                report.status_extended = (
                    f"API key {key.name} creation date have more than 90 days."
                )
            findings.append(report)

        return findings
