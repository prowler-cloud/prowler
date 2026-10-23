from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_leaked_password_protection_enabled(Check):
    """Check that Supabase Auth rejects passwords found in known breaches.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.password_hibp_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.password_hibp_enabled:
                report.status = "PASS"
                report.status_extended = f"Project {config.name} rejects leaked passwords through HaveIBeenPwned."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} accepts passwords that appear in known data breaches."
            findings.append(report)
        return findings
