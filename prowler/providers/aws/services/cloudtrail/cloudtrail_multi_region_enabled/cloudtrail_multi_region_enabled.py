from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_multi_region_enabled(Check):
    def execute(self):
        findings = []
        actual_region = None
        for trail in cloudtrail_client.trails:
            report = Check_Report_AWS(self.metadata())
            report.region = trail.region
            if trail.name:  # Check if there are trails in region
                # Check if region has changed and add report of previous region
                if actual_region != trail.region:
                    if report:  # Check if it not the beginning
                        findings.append(report)
                trail_in_region = False
                if not trail_in_region:
                    if trail.is_logging:
                        report.status = "PASS"
                        if trail.is_multiregion:
                            report.status_extended = (
                                f"Trail {trail.name} is multiregion and it is logging"
                            )
                        else:
                            report.status_extended = f"Trail {trail.name} is not multiregion and it is logging"
                        report.resource_id = trail.name
                        report.resource_arn = trail.arn
                        trail_in_region = True  # Trail enabled in region
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            "No CloudTrail trails enabled and logging were found"
                        )
                        report.region = cloudtrail_client.region
                        report.resource_arn = "No trails"
                        report.resource_id = "No trails"
                actual_region = trail.region
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "No CloudTrail trails enabled and logging were found"
                )
                report.resource_arn = "No trails"
                report.resource_id = "No trails"
                report.region = cloudtrail_client.region
                findings.append(report)

        return findings
