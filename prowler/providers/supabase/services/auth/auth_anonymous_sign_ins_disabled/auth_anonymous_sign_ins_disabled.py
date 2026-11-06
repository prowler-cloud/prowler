from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_anonymous_sign_ins_disabled(Check):
    """Check that anonymous sign-ins are disabled unless deliberately used.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.external_anonymous_users_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if not config.external_anonymous_users_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.name} has anonymous sign-ins disabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} allows anonymous sign-ins, which receive the authenticated role."
            findings.append(report)
        return findings
