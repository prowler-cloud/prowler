from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class account_api_token_recently_used(Check):
    """Ensure that active API tokens have been used recently.

    Long-unused tokens are forgotten credentials: they keep their permissions,
    are rarely monitored, and should be revoked.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        max_days = account_client.audit_config.get("max_unused_api_token_days", 90)
        threshold = datetime.now(timezone.utc) - timedelta(days=max_days)

        for token in account_client.tokens:
            if token.status != "active":
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=token)
            label = f"API token {token.name} ({token.owner}-owned)"

            if token.last_used_on:
                last_used = _as_utc(token.last_used_on)
                if last_used >= threshold:
                    report.status = "PASS"
                    report.status_extended = f"{label} was last used on {last_used.date().isoformat()}, within the last {max_days} days."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"{label} has not been used since {last_used.date().isoformat()}, more than {max_days} days ago."
            elif token.issued_on and _as_utc(token.issued_on) >= threshold:
                report.status = "PASS"
                report.status_extended = f"{label} has never been used but was issued within the last {max_days} days."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"{label} has never been used and was issued more than {max_days} days ago."
                    if token.issued_on
                    else f"{label} has never been used."
                )
            findings.append(report)
        return findings
