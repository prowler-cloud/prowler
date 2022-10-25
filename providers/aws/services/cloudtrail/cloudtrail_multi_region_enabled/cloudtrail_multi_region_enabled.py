from lib.check.models import Check, Check_Report
from providers.aws.services.cloudtrail.cloudtrail_client import cloudtrail_client


class cloudtrail_multi_region_enabled(Check):
    def execute(self):
        findings = []
        actual_region = None
        for trail in cloudtrail_client.trails:
            report = Check_Report(self.metadata)
            if trail.name != "not_found":  # Check if there are trails in region
                if (
                    actual_region != trail.region
                ):  # Check if region has changed and add report of previous region
                    if report:  # Check if it not the beginning
                        findings.append(report)
                    report.region = trail.region
                    report.resource_id = trail.name
                    report.resource_arn = trail.trail_arn
                    trail_in_region = False
                    if not trail_in_region:
                        if trail.is_logging:
                            report.status = "PASS"
                            if trail.is_multiregion:
                                report.status_extended = f"Trail {trail.name} is multiregion and it is logging"
                            else:
                                report.status_extended = f"Trail {trail.name} is not multiregion and it is logging"
                            trail_in_region = True  # Trail enabled in region
                        else:
                            report.status = "FAIL"
                            if trail.is_multiregion:
                                report.status_extended = f"Trail {trail.name} is multiregion but it is not logging"
                            else:
                                report.status_extended = f"Trail {trail.name} is not multiregion and it is not logging"
                actual_region = trail.region
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "No CloudTrail trails enabled and logging were found"
                )
                report.resource_arn = "No trails"
                report.resource_id = "No trails"
                findings.append(report)

        return findings
