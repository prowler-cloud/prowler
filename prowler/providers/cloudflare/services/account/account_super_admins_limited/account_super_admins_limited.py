from prowler.lib.check.models import Check, CheckReportCloudflare
from prowler.providers.cloudflare.services.account.account_client import (
    account_client,
)


class account_super_admins_limited(Check):
    """Ensure that the number of Super Administrators in an account is limited.

    Super Administrators hold every privilege, including managing members, API
    tokens and billing. Keeping this group small limits the blast radius of a
    compromised account member.
    """

    def execute(self) -> list[CheckReportCloudflare]:
        findings = []
        max_super_admins = account_client.audit_config.get("max_super_admins", 3)
        members_by_account: dict[str, list] = {}
        for member in account_client.members:
            members_by_account.setdefault(member.account_id, []).append(member)

        for account in account_client.accounts:
            members = members_by_account.get(account.id)
            # Members could not be listed for this account
            if not members:
                continue
            super_admins = sorted(
                member.name
                for member in members
                if member.status == "accepted" and member.is_super_admin
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
