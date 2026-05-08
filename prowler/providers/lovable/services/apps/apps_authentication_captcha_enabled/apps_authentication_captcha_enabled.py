from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_authentication_captcha_enabled(Check):
    """CAPTCHA / bot protection must be enabled on signup and login forms."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)
            if not app.auth_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) does not expose authentication; "
                    "CAPTCHA is not applicable."
                )
            elif app.captcha_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has CAPTCHA enabled on auth forms."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) exposes authentication without "
                    "CAPTCHA, allowing automated credential stuffing."
                )
            findings.append(report)
        return findings
