from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.securityhub.securityhub_client import (
    securityhub_client,
)


class securityhub_delegated_admin_enabled_all_regions(Check):
    """Ensure Security Hub has a delegated admin and is enabled in all regions.

    This check verifies that:
    1. A delegated administrator account is configured for Security Hub
    2. Security Hub is active (ACTIVE status) in each region
    3. Organization auto-enable is configured for new member accounts
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check for each region.
        """
        findings = []

        # Build a set of regions that have an organization admin account configured
        regions_with_admin = {
            admin.region
            for admin in securityhub_client.organization_admin_accounts
            if admin.admin_status == "ENABLED"
        }
        admin_lookup_failed = securityhub_client.organization_admin_lookup_failed

        for securityhub in securityhub_client.securityhubs:
            report = Check_Report_AWS(metadata=self.metadata(), resource=securityhub)

            # Check if this region has a delegated admin
            has_delegated_admin = securityhub.region in regions_with_admin

            # Check if hub is active
            hub_active = securityhub.status == "ACTIVE"

            # Check if auto-enable is configured for organization members
            auto_enable_on = securityhub.organization_auto_enable

            # Determine overall status
            issues = []
            if admin_lookup_failed:
                issues.append("delegated administrator status could not be determined")
            elif not has_delegated_admin:
                issues.append("no delegated administrator configured")
            if not hub_active:
                issues.append("Security Hub not enabled")
            if (
                hub_active
                and securityhub.organization_config_available
                and not auto_enable_on
            ):
                # Only report auto-enable issue if hub is active and org config data
                # is available (i.e., we could actually read AutoEnable from the API).
                issues.append("organization auto-enable not configured")

            if issues:
                report.status = "FAIL"
                report.status_extended = (
                    f"Security Hub in region {securityhub.region} has issues: "
                    f"{', '.join(issues)}."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Security Hub in region {securityhub.region} has delegated "
                    f"admin configured with hub active and organization auto-enable "
                    f"enabled."
                )

            # Support muting non-default regions if configured
            if report.status == "FAIL" and (
                securityhub_client.audit_config.get("mute_non_default_regions", False)
                and securityhub.region != securityhub_client.region
            ):
                report.muted = True

            findings.append(report)

        return findings
