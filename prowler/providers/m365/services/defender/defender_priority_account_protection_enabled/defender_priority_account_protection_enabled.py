from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_priority_account_protection_enabled(Check):
    """Check if priority account protection is enabled.

    Priority account protection applies enhanced monitoring and protection to
    high-value accounts. Its tenant-level flag ``EnablePriorityAccountProtection``
    (from Get-EmailTenantSettings) should be enabled.

    Note: This check covers the tenant-level enablement flag only. The full control
    also requires priority accounts to be tagged and alert policies to be configured,
    which must be verified manually.

    - PASS: Priority account protection is enabled at the tenant level.
    - FAIL: Priority account protection is disabled at the tenant level.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        settings = defender_client.email_tenant_settings
        if not settings:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=settings,
            resource_name="Email Tenant Settings",
            resource_id="emailTenantSettings",
        )
        report.status = "FAIL"
        report.status_extended = (
            "Priority account protection is not enabled at the tenant level."
        )

        if settings.priority_account_protection_enabled:
            report.status = "PASS"
            report.status_extended = (
                "Priority account protection is enabled at the tenant level."
            )

        findings.append(report)
        return findings
