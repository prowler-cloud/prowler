from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_api_token_expiration_set(Check):
    """Ensure that active API tokens have an expiration date."""

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
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
