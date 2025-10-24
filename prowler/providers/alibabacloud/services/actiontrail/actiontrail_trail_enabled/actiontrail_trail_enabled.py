"""
Check: actiontrail_trail_enabled

Ensures that at least one ActionTrail trail is enabled to log API activity for security auditing.
ActionTrail records API calls and events for compliance, security analysis, and troubleshooting.

Risk Level: HIGH
Compliance: CIS Alibaba Cloud Foundations Benchmark
"""

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import actiontrail_client


class actiontrail_trail_enabled(Check):
    """Check if at least one ActionTrail trail is enabled"""

    def execute(self):
        """Execute the actiontrail_trail_enabled check"""
        findings = []

        # Check if there's at least one enabled trail
        enabled_trails = [trail for trail in actiontrail_client.trails.values() if trail.status == "Enabled"]

        # Create a report for the account
        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=type('obj', (object,), {
            'id': 'actiontrail-configuration',
            'name': 'ActionTrail Configuration',
            'arn': f"acs:actiontrail::{actiontrail_client.account_id}:configuration",
            'region': 'global'
        })())

        report.account_uid = actiontrail_client.account_id
        report.region = "global"
        report.resource_id = "actiontrail-configuration"
        report.resource_arn = f"acs:actiontrail::{actiontrail_client.account_id}:configuration"

        if len(enabled_trails) > 0:
            trail_names = [trail.name for trail in enabled_trails]
            report.status = "PASS"
            report.status_extended = f"ActionTrail has {len(enabled_trails)} enabled trail(s): {', '.join(trail_names)}."
        else:
            report.status = "FAIL"
            report.status_extended = "No enabled ActionTrail trails found. Enable at least one trail to log API activity for security auditing and compliance."

        findings.append(report)
        return findings
