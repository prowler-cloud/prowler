from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.lib.service.scope import (
    account_scope,
    manual_account_report,
)
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)

DEFAULT_MAX_SUPER_ADMINS = 3


class account_super_admins_limited(Check):
    """Ensure that the number of Super Administrators in an account is limited.

    Super Administrators hold every privilege, including managing members, API
    tokens and billing. Keeping this group small limits the blast radius of a
    compromised account member.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        """Count the accepted Super Administrators of every audited account.

        Returns:
            One finding per account: PASS within the configured maximum
            (``max_super_admins``, default 3), FAIL above it, or MANUAL when the
            members could not be listed.
        """
        findings = []
        max_super_admins = (
            account_client.audit_config.get("max_super_admins")
            or DEFAULT_MAX_SUPER_ADMINS
        )
        settings_by_id = {account.id: account for account in account_client.accounts}

        for account_id in sorted(account_client.members_failed_accounts):
            report = manual_account_report(self, account_client, account_id, "")
            report.status_extended = (
                f"Cannot count Super Administrators for account {report.resource_name}: "
                "the account members could not be listed. Verify that the scanning "
                "token has the Account Settings Read permission."
            )
            findings.append(report)

        for account_id in account_client.audited_accounts:
            if account_id not in account_client.members_listed_accounts:
                continue
            account = settings_by_id.get(account_id) or account_scope(
                account_client, account_id
            )
            super_admins = sorted(
                member.name
                for member in account_client.members
                if member.account_id == account_id
                and member.status == "accepted"
                and member.is_super_admin
            )
            report = CheckReportCloudflare(metadata=self.metadata(), resource=account)
            if len(super_admins) <= max_super_admins:
                report.status = "PASS"
                report.status_extended = f"Account {account.name} has {len(super_admins)} Super Administrator(s), within the limit of {max_super_admins}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Account {account.name} has {len(super_admins)} Super Administrators, exceeding the limit of {max_super_admins}: {', '.join(super_admins)}."
            findings.append(report)
        return findings
