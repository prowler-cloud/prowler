from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_mfa_enrollment_enabled(Check):
    """Check that users can enroll a second authentication factor.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.mfa_totp_enroll_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.mfa_enrollment_enabled:
                report.status = "PASS"
                report.status_extended = f"Project {config.name} lets users enroll multi-factor authentication."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} has every multi-factor enrollment method disabled."
            findings.append(report)
        return findings
