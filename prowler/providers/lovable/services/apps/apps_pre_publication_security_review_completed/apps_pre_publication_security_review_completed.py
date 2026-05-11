from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_pre_publication_security_review_completed(Check):
    """Lovable's built-in 'Review Security' check must have been run with no
    open findings before an app is published."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            if not app.is_published:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) is not yet published; "
                    "security review is not gating."
                )
            elif not app.security_review_run:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) was published without running "
                    "Lovable's built-in security review."
                )
            elif app.security_review_findings > 0:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) has "
                    f"{app.security_review_findings} unresolved security review "
                    f"finding(s) (last run: {app.security_review_last_run})."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) passed Lovable's built-in "
                    f"security review (last run: {app.security_review_last_run})."
                )
            findings.append(report)
        return findings
