from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.lib.constants import GEMINI_SERVICE_NAME
from prowler.providers.gcp.services.apikeys.apikeys_client import apikeys_client
from prowler.providers.gcp.services.serviceusage.serviceusage_client import (
    serviceusage_client,
)


class apikeys_api_restricted_with_gemini_api(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []

        for key in apikeys_client.keys:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=key,
                location=apikeys_client.region,
            )
            report.status = "PASS"
            report.status_extended = f"API key {key.name} has restrictions configured."

            genlang_enabled = any(
                active_service.name == GEMINI_SERVICE_NAME
                for active_service in serviceusage_client.active_services.get(
                    key.project_id, []
                )
            )

            if not genlang_enabled:
                report.status = "PASS"
                report.status_extended = f"Gemini (Generative Language) API is not enabled for project {key.project_id} of key {key.name}"
                findings.append(report)
                continue

            key_restrictions = key.restrictions.get("apiTargets", [])

            if len(key_restrictions) > 1 and any(
                target.get("service") == GEMINI_SERVICE_NAME
                for target in key_restrictions
            ):
                report.status = "FAIL"
                report.status_extended = f"API key {key.name} has access to Gemini (Generative Language) API as well as other APIs."

            elif not key_restrictions or any(
                target.get("service") == "cloudapis.googleapis.com"
                for target in key_restrictions
            ):
                report.status = "FAIL"
                report.status_extended = f"API key {key.name} does not have restrictions configured and Gemini (Generative Language) API is enabled for project {key.project_id}."

            findings.append(report)

        return findings
