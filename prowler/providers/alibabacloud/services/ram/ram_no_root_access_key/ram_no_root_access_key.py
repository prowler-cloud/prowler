from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.ram.ram_client import ram_client


class ram_no_root_access_key(Check):
    """Check if root account has no access keys."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        report = CheckReportAlibabaCloud(metadata=self.metadata(), resource={})
        report.region = ram_client.region
        report.resource_id = "<root_account>"
        report.resource_arn = f"acs:ram::{ram_client.audited_account}:root"

        # Check if we're authenticated as root account
        # Use the is_root flag from identity (set via STS GetCallerIdentity)
        is_root = ram_client.provider.identity.is_root

        if not is_root:
            # If authenticated as RAM user, we can't verify root account access keys
            report.status = "MANUAL"
            report.status_extended = "Cannot verify root account access keys: authenticated as RAM user. This check requires root account credentials."
        elif ram_client.root_access_keys:
            report.status = "FAIL"
            report.status_extended = "Root account has access keys."
        else:
            report.status = "PASS"
            report.status_extended = "Root account does not have access keys."

        findings.append(report)

        return findings
