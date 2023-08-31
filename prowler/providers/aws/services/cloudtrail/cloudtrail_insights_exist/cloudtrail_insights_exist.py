from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_insights_exist(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            if trail.is_logging:
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.resource_tags = trail.tags
                report.status = "FAIL"
                report.status_extended = f"Trail {trail.name} does not have insight selectors and it is logging."
                if trail.has_insight_selectors:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Trail {trail.name} has insight selectors and it is logging."
                    )
                findings.append(report)
        return findings
