from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client

DEFAULT_AUTH_OTP_EXPIRY_SECONDS = 3600


class auth_otp_expiry_within_threshold(Check):
    """Check that email one-time passcodes expire within the recommended window.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        max_seconds = auth_client.audit_config.get(
            "auth_otp_expiry_seconds", DEFAULT_AUTH_OTP_EXPIRY_SECONDS
        )
        for config in auth_client.configs.values():
            if config.mailer_otp_exp is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.mailer_otp_exp <= max_seconds:
                report.status = "PASS"
                report.status_extended = f"Project {config.name} expires email OTPs after {config.mailer_otp_exp} seconds (threshold {max_seconds})."
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} keeps email OTPs valid for {config.mailer_otp_exp} seconds, above the threshold of {max_seconds}."
            findings.append(report)
        return findings
