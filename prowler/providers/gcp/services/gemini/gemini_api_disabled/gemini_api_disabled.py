from prowler.lib.check.models import Check, Check_Report_GCP
from prowler.providers.gcp.lib.constants import GEMINI_SERVICE_NAME
from prowler.providers.gcp.services.serviceusage.serviceusage_client import (
    serviceusage_client,
)


class gemini_api_disabled(Check):
    def execute(self) -> Check_Report_GCP:
        findings = []

        for project_id in serviceusage_client.project_ids:
            report = Check_Report_GCP(
                metadata=self.metadata(),
                resource=serviceusage_client.projects[project_id],
                resource_id=GEMINI_SERVICE_NAME,
                resource_name="Gemini (Generative Language) API",
                project_id=project_id,
                location=serviceusage_client.region,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"Gemini (Generative Language) API is enabled for project {project_id}"
            )

            genlang_enabled = any(
                active_service.name == GEMINI_SERVICE_NAME
                for active_service in serviceusage_client.active_services.get(
                    project_id, []
                )
            )

            if not genlang_enabled:
                report.status = "PASS"
                report.status_extended = f"Gemini (Generative Language) API is disabled for project {project_id}"

            findings.append(report)

        return findings
