from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.guardduty.guardduty_client import guardduty_client


class guardduty_delegated_admin_enabled_all_regions(Check):
    """Ensure GuardDuty has a delegated admin and is enabled in all regions.

    This check verifies that:
    1. A delegated administrator account is configured for GuardDuty
    2. GuardDuty detectors are enabled in each region
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
            for admin in guardduty_client.organization_admin_accounts
            if admin.admin_status == "ENABLED"
        }

        for detector in guardduty_client.detectors:
            report = Check_Report_AWS(metadata=self.metadata(), resource=detector)

            # Check if this region has a delegated admin
            has_delegated_admin = detector.region in regions_with_admin

            # The lookup is tracked per region so that a failure in one region does
            # not mask the result of the others. A failure is only relevant when no
            # delegated admin was found: if one was, the status is known.
            admin_lookup_failed = (
                not has_delegated_admin
                and detector.region
                in guardduty_client.organization_admin_lookup_failed_regions
            )

            # Check if detector is enabled
            detector_enabled = detector.enabled_in_account and detector.status

            # Check if auto-enable is configured for organization members
            auto_enable_configured = detector.organization_auto_enable_members in (
                "NEW",
                "ALL",
            )

            # Determine overall status
            issues = []
            if not admin_lookup_failed and not has_delegated_admin:
                issues.append("no delegated administrator configured")
            if not detector_enabled:
                issues.append("detector not enabled")
            if not auto_enable_configured and detector.organization_config_available:
                # Only report auto-enable issue if org config data is available
                issues.append("organization auto-enable not configured")

            if issues:
                report.status = "FAIL"
                report.status_extended = (
                    f"GuardDuty in region {detector.region} has issues: "
                    f"{', '.join(issues)}."
                )
                if admin_lookup_failed:
                    report.status_extended = (
                        f"{report.status_extended[:-1]}; the delegated administrator "
                        f"status could not be determined."
                    )
            elif admin_lookup_failed:
                # Not being able to read the delegated administrator is a lack of
                # visibility, not a misconfiguration: the API is only available to
                # the management or delegated administrator account.
                report.status = "MANUAL"
                report.status_extended = (
                    f"GuardDuty delegated administrator status in region "
                    f"{detector.region} could not be determined; run this check "
                    f"from the organization management or delegated administrator "
                    f"account."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"GuardDuty in region {detector.region} has delegated admin "
                    f"configured with detector enabled and organization auto-enable active."
                )

            # Support muting non-default regions if configured
            if report.status == "FAIL" and (
                guardduty_client.audit_config.get("mute_non_default_regions", False)
                and detector.region != guardduty_client.region
            ):
                report.muted = True

            findings.append(report)

        return findings
