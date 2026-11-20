from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.projects.projects_client import projects_client

DEFAULT_POSTGREST_MAX_ROWS = 1000


class projects_postgrest_max_rows_limited(Check):
    """Check that the Data API caps the number of rows a single request can return.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        max_rows = projects_client.audit_config.get(
            "postgrest_max_rows", DEFAULT_POSTGREST_MAX_ROWS
        )
        for project in projects_client.projects.values():
            if project.postgrest_max_rows is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=project)
            if project.postgrest_max_rows <= max_rows:
                report.status = "PASS"
                report.status_extended = f"Project {project.name} limits Data API responses to {project.postgrest_max_rows} rows (threshold {max_rows})."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} allows Data API responses of {project.postgrest_max_rows} rows, above the threshold of {max_rows}."
            findings.append(report)
        return findings
