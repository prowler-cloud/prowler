from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)
from prowler.providers.cloudflare.services.account.token_manual import (
    token_listing_manual_reports,
)


class account_api_token_expiration_set(Check):
    """Ensure that active API tokens have an expiration date."""

    def execute(self) -> list[CheckReportCloudflare]:
        """Evaluate the expiration date of every active API token.

        Returns:
            PASS for tokens with an expiration date, FAIL for tokens without one,
            and MANUAL per account whose account-owned tokens could not be listed.
        """
        findings = token_listing_manual_reports(
            self, account_client, "expiration dates"
        )
        for token in account_client.tokens:
            if token.status != "active":
                continue
            report = CheckReportCloudflare(
                metadata=self.metadata(),
                resource=token,
                resource_name=token.unique_name,
            )
            if token.expires_on:
                report.status = "PASS"
                report.status_extended = f"API token {token.name} ({token.owner}-owned) expires on {token.expires_on.isoformat()}."
            else:
                report.status = "FAIL"
                report.status_extended = f"API token {token.name} ({token.owner}-owned) does not have an expiration date."
            findings.append(report)
        return findings
