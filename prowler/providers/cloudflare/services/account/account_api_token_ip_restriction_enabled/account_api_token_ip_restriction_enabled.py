from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_api_token_ip_restriction_enabled(Check):
    """Ensure that active API tokens have client IP address filtering configured."""

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        for token in account_client.tokens:
            if token.status != "active":
                continue
            report = CheckReportCloudflare(metadata=self.metadata(), resource=token)
            if token.ip_allow_list or token.ip_deny_list:
                report.status = "PASS"
                report.status_extended = f"API token {token.name} ({token.owner}-owned) has client IP address filtering configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"API token {token.name} ({token.owner}-owned) does not have client IP address filtering configured."
            findings.append(report)
        return findings
