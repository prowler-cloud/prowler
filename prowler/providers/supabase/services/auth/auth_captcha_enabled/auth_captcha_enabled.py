from typing import List

from prowler.lib.check.models import Check, CheckReportSupabase
from prowler.providers.supabase.services.auth.auth_client import auth_client


class auth_captcha_enabled(Check):
    """Check that bot protection is enabled on Supabase Auth endpoints.

    Resources whose setting could not be read are skipped instead of failed.
    """

    def execute(self) -> List[CheckReportSupabase]:
        """Return one finding per project."""
        findings = []
        for config in auth_client.configs.values():
            if config.security_captcha_enabled is None:
                continue
            report = CheckReportSupabase(metadata=self.metadata(), resource=config)
            if config.security_captcha_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Project {config.name} protects sign-up and sign-in with CAPTCHA."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"Project {config.name} exposes sign-up and sign-in without CAPTCHA protection."
            findings.append(report)
        return findings
