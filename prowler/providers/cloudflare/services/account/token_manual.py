"""Shared MANUAL reporting for the Cloudflare API token checks."""

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.service.scope import manual_account_report


def token_listing_manual_reports(
    check: Check, client, requirement: str
) -> list[CheckReportCloudflare]:
    """One MANUAL finding per account whose account-owned tokens could not be listed.

    Args:
        check: The token check emitting the findings.
        client: The account service client.
        requirement: What the check evaluates, used in the message.

    Returns:
        The account-level MANUAL findings.
    """
    reports = []
    for account_id in sorted(client.tokens_failed_accounts):
        report = manual_account_report(check, client, account_id, "")
        report.status_extended = (
            f"Cannot evaluate {requirement} for account-owned API tokens of account "
            f"{report.resource_name}: the tokens could not be listed. Account-owned "
            "tokens are only visible to tokens created by a Super Administrator with "
            "the Account API Tokens Read permission."
        )
        reports.append(report)
    for account_id in sorted(
        getattr(client, "user_tokens_unattributed_accounts", set())
        - set(client.tokens_failed_accounts)
    ):
        report = manual_account_report(check, client, account_id, "")
        report.status_extended = (
            f"Cannot evaluate {requirement} for zone-scoped user API tokens of account "
            f"{report.resource_name}: the zones could not be listed to attribute them "
            "to an account. Verify that the scanning token has the Zone Read permission."
        )
        reports.append(report)
    return reports
