from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_authentication_rate_limit_enabled(Check):
    """Auth endpoints (signup / login / password reset) must be rate limited."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)
            if not app.auth_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has no authentication "
                    "endpoints to rate-limit."
                )
            elif app.auth_rate_limit_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) rate-limits authentication "
                    "endpoints."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) does not rate-limit "
                    "signup/login/password reset endpoints."
                )
            findings.append(report)
        return findings
