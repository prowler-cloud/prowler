from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_refresh_token_rotation_enabled(Check):
    """Check that refresh tokens are rotated on every use.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.refresh_token_rotation_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.refresh_token_rotation_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.name} rotates refresh tokens on use."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} reuses refresh tokens, so a stolen token stays valid indefinitely."
            findings.append(report)
        return findings
