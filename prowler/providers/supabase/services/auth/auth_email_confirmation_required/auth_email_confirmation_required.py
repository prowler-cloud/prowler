from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_email_confirmation_required(Check):
    """Check that new email sign-ups must confirm their address.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.mailer_autoconfirm is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if not config.mailer_autoconfirm:
                report.status = "PASS"
                report.status_extended = f"Project {config.name} requires email confirmation before a sign-up is active."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} auto-confirms email sign-ups without verifying the address."
            findings.append(report)
        return findings
