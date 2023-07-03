from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.services.apikeys.apikeys_client import apikeys_client


class apikeys_api_restrictions_configured(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []
        for key in apikeys_client.keys:
            report = Check_Report_GCP(self.metadata())
            report.project_id = key.project_id
            report.resource_id = key.id
            report.resource_name = key.name
            report.status = "PASS"
            report.status_extended = f"API key {key.name} has restrictions configured."
            if key.restrictions == {} or any(
                [
                    target.get("service") == "cloudapis.googleapis.com"
                    for target in key.restrictions["apiTargets"]
                ]
            ):
                report.status = "FAIL"
                report.status_extended = (
                    f"API key {key.name} doens't have restrictions configured."
                )
            findings.append(report)

        return findings
