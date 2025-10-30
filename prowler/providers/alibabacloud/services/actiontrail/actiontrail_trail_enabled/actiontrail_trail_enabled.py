from dataclasses import dataclass

from prowler.lib.check.models import Check, Check_Report_AlibabaCloud
from prowler.providers.alibabacloud.services.actiontrail.actiontrail_client import (
    actiontrail_client,
)


@dataclass
class ActionTrailConfig:
    id: str
    name: str
    arn: str
    region: str


class actiontrail_trail_enabled(Check):
    def execute(self):
        findings = []
        enabled_trails = [
            trail
            for trail in actiontrail_client.trails.values()
            if trail.status == "Enabled"
        ]

        config = ActionTrailConfig(
            id="actiontrail-configuration",
            name="ActionTrail Configuration",
            arn=f"acs:actiontrail::{actiontrail_client.account_id}:configuration",
            region="global",
        )

        report = Check_Report_AlibabaCloud(metadata=self.metadata(), resource=config)
        report.status = "FAIL"
        report.status_extended = "No enabled ActionTrail trails found."
        if len(enabled_trails) > 0:
            trail_names = [trail.name for trail in enabled_trails]
            report.status = "PASS"
            report.status_extended = f"ActionTrail has {len(enabled_trails)} enabled trail(s): {', '.join(trail_names)}."
        findings.append(report)
        return findings
