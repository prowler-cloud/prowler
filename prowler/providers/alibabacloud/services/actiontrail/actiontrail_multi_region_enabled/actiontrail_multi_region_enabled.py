from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import (
    actiontrail_client,
)


class actiontrail_multi_region_enabled(Check):
    """Check if ActionTrail is configured to export copies of all log entries."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Check if there's at least one multi-region trail that is enabled
        multi_region_trails = []
        for trail in actiontrail_client.trails.values():
            if trail.trail_region == "All" and trail.status == "Enable":
                multi_region_trails.append(trail)

        # Create a single report for the overall check
        report = CheckReportAlibabaCloud(metadata=self.metadata(), resource={})
        report.region = actiontrail_client.region
        report.resource_id = actiontrail_client.audited_account
        report.resource_arn = (
            f"acs:actiontrail::{actiontrail_client.audited_account}:trail"
        )

        if multi_region_trails:
            # At least one multi-region trail is enabled
            trail_names = [trail.name for trail in multi_region_trails]
            report.status = "PASS"
            report.status_extended = (
                f"ActionTrail is configured with {len(multi_region_trails)} multi-region trail(s) "
                f"that are enabled: {', '.join(trail_names)}. "
                "These trails export copies of all log entries across all regions."
            )
        else:
            # Check if there are any trails at all
            if actiontrail_client.trails:
                # There are trails but none are multi-region or enabled
                enabled_trails = [
                    t
                    for t in actiontrail_client.trails.values()
                    if t.status == "Enable"
                ]
                multi_region_trails_disabled = [
                    t
                    for t in actiontrail_client.trails.values()
                    if t.trail_region == "All" and t.status != "Enable"
                ]

                if enabled_trails and not multi_region_trails_disabled:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ActionTrail has {len(enabled_trails)} enabled trail(s), but none are configured "
                        "for multi-region logging (TrailRegion is not set to 'All'). "
                        "Multi-region trails are required to capture events from all regions."
                    )
                elif multi_region_trails_disabled:
                    trail_names = [t.name for t in multi_region_trails_disabled]
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ActionTrail has multi-region trail(s) but they are disabled: {', '.join(trail_names)}. "
                        "Enable the multi-region trail(s) to export copies of all log entries."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        "ActionTrail has trails configured, but none are enabled or configured for multi-region logging. "
                        "At least one trail with TrailRegion set to 'All' and Status set to 'Enable' is required."
                    )
            else:
                # No trails configured at all
                report.status = "FAIL"
                report.status_extended = (
                    "ActionTrail is not configured. No trails exist. "
                    "Create at least one multi-region trail (TrailRegion='All') and enable it "
                    "to export copies of all log entries across all regions."
                )

        findings.append(report)
        return findings
