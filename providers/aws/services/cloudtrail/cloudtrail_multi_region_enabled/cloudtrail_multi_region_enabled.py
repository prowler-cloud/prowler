from lib.check.models import Check, Check_Report
from providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client


class cloudtrail_multi_region_enabled(Check):
    def execute(self) -> Check_Report:
        findings = []
        for region in cloudtrail_client.trail_regions:
            report = Check_Report(self.metadata)
            report.status = "FAIL"
            report.status_extended = (
                "No CloudTrail trails enabled and logging were found"
            )
            report.resource_arn = "No trails"
            report.resource_id = "No trails"
            report.region = region
            for trail in cloudtrail_client.trails:
                if trail.region == region:
                    if trail.is_logging:
                        report.status = "PASS"
                        report.resource_id = trail.name
                        report.resource_arn = trail.trail_arn
                        if trail.is_multiregion:
                            report.status_extended = (
                                f"Trail {trail.name} is multiregion and it is logging"
                            )
                        else:
                            report.status_extended = f"Trail {trail.name} is not multiregion and it is logging"
                        break

            findings.append(report)

        return findings
