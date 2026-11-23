"""Shared MANUAL reporting for the Cloudflare R2 checks."""

from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.service.scope import manual_account_report


def r2_manual_reports(
    check: Check, client, failed_accounts: set[str], requirement: str
) -> list[CheckReportCloudflare]:
    """One MANUAL finding per account whose R2 data could not be retrieved.

    Args:
        check: The R2 check emitting the findings.
        client: The R2 service client.
        failed_accounts: Accounts where the data this check needs failed to load.
        requirement: What the check evaluates, used in the message.

    Returns:
        Account-level MANUAL findings, including accounts whose buckets could not
        be listed at all.
    """
    reports = []
    for account_id in sorted(set(failed_accounts) | client.list_failed_accounts):
        report = manual_account_report(check, client, account_id, "")
        report.status_extended = (
            f"Cannot evaluate {requirement} for R2 buckets in account "
            f"{report.resource_name}: the R2 configuration could not be retrieved. "
            "Verify that the scanning token has the Workers R2 Storage Read permission."
        )
        reports.append(report)
    return reports
