from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)

maximum_time_without_logging = 1


class cloudtrail_cloudwatch_logging_enabled(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            if trail.name:
                report = Check_Report_AWS(self.metadata())
                report.region = trail.region
                report.resource_id = trail.name
                report.resource_arn = trail.arn
                report.status = "PASS"
                if trail.is_multiregion:
                    report.status_extended = (
                        f"Multiregion trail {trail.name} has been logging the last 24h"
                    )
                else:
                    report.status_extended = f"Single region trail {trail.name} has been logging the last 24h"
                if trail.latest_cloudwatch_delivery_time:
                    last_log_delivery = (
                        datetime.now().replace(tzinfo=timezone.utc)
                        - trail.latest_cloudwatch_delivery_time
                    )
                    if last_log_delivery > timedelta(days=maximum_time_without_logging):
                        report.status = "FAIL"
                        if trail.is_multiregion:
                            report.status_extended = f"Multiregion trail {trail.name} is not logging in the last 24h"
                        else:
                            report.status_extended = f"Single region trail {trail.name} is not logging in the last 24h"
                else:
                    report.status = "FAIL"
                    if trail.is_multiregion:
                        report.status_extended = f"Multiregion trail {trail.name} is not configured to deliver logs"
                    else:
                        report.status_extended = f"Single region trail {trail.name} is not configured to deliver logs"
                findings.append(report)

        return findings
