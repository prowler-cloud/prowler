from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)
from prowler.providers.cloudflare.services.account.token_manual import (
    token_listing_manual_reports,
)

DEFAULT_MAX_UNUSED_DAYS = 90


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class account_api_token_recently_used(Check):
    """Ensure that active API tokens have been used recently.

    Long-unused tokens are forgotten credentials: they keep their permissions,
    are rarely monitored, and should be revoked.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate when every active API token was last used.

        Returns:
            PASS for tokens used (or issued) within ``max_unused_api_token_days``
            (default 90), FAIL for older ones, MANUAL for tokens whose age is
            unknown and per account whose account-owned tokens could not be listed.
        """
        findings = token_listing_manual_reports(self, account_client, "recent use")
        max_days = (
            account_client.audit_config.get("max_unused_api_token_days")
            or DEFAULT_MAX_UNUSED_DAYS
        )
        threshold = datetime.now(timezone.utc) - timedelta(days=max_days)

        for token in account_client.tokens:
            if token.status != "active":
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=token,
                resource_name=token.unique_name,
            )
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
            elif token.issued_on:
                report.status = "FAIL"
                report.status_extended = f"{label} has never been used and was issued more than {max_days} days ago."
            else:
                # Neither last use nor issue date is known: the age cannot be evaluated.
                report.status = "MANUAL"
                report.status_extended = f"{label} has no recorded use or issue date; review whether it is still needed."
            findings.append(report)
        return findings
