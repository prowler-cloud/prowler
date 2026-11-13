from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client

DEFAULT_AUTH_PASSWORD_MIN_LENGTH = 8


class auth_password_min_length(Check):
    """Check that Supabase Auth requires passwords of a minimum length.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        min_length = auth_client.audit_config.get(
            "auth_password_min_length", DEFAULT_AUTH_PASSWORD_MIN_LENGTH
        )
        for config in auth_client.configs.values():
            if config.password_min_length is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.password_min_length >= min_length:
                report.status = "PASS"
                report.status_extended = f"Project {config.name} requires passwords of at least {config.password_min_length} characters (threshold {min_length})."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} accepts passwords of only {config.password_min_length} characters, below the threshold of {min_length}."
            findings.append(report)
        return findings
