from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.projects.projects_client import projects_client


class projects_legacy_api_keys_disabled(Check):
    """Check that the legacy JWT based anon and service_role API keys are disabled.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for project in projects_client.projects.values():
            if project.legacy_api_keys_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=project)
            if not project.legacy_api_keys_enabled:
                report.status = "PASS"
                report.status_extended = f"Project {project.name} has the legacy anon and service_role API keys disabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {project.name} still accepts the legacy anon and service_role JWT API keys."
            findings.append(report)
        return findings
