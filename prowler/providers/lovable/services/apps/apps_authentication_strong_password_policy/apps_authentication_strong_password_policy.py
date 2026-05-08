from prowler.lib.check.models import Check, CheckReportLovable
from prowler.providers.lovable.config import MIN_PASSWORD_LENGTH
from prowler.providers.lovable.services.apps.apps_client import apps_client


class apps_authentication_strong_password_policy(Check):
    """Password policy must require >=8 chars, uppercase, lowercase, and number."""

    def execute(self) -> list[CheckReportLovable]:
        findings: list[CheckReportLovable] = []
        for app in apps_client.apps.values():
            report = CheckReportLovable(metadata=self.metadata(), resource=app)

            if not app.auth_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) does not use password auth; "
                    "policy is not applicable."
                )
                findings.append(report)
                continue

            problems: list[str] = []
            if app.password_min_length < MIN_PASSWORD_LENGTH:
                problems.append(
                    f"min length {app.password_min_length} < {MIN_PASSWORD_LENGTH}"
                )
            if not app.password_requires_uppercase:
                problems.append("uppercase required = false")
            if not app.password_requires_lowercase:
                problems.append("lowercase required = false")
            if not app.password_requires_number:
                problems.append("number required = false")

            if problems:
                report.status = "FAIL"
                report.status_extended = (
                    f"App {app.name} ({app.id}) password policy is weak: "
                    f"{'; '.join(problems)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"App {app.name} ({app.id}) enforces a strong password "
                    "policy (min length, uppercase, lowercase, and number)."
                )
            findings.append(report)
        return findings
