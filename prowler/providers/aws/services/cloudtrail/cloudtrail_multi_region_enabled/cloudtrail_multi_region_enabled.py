from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_multi_region_enabled(Check):
    def execute(self):
        findings = []
        for region in cloudtrail_client.regional_clients.keys():
            report = Check_Report_AWS(self.metadata())
            report.region = region
            for trail in cloudtrail_client.trails:
                if trail.region == region:
                    if trail.is_logging:
                        report.status = "PASS"
                        report.resource_id = trail.name
                        report.resource_arn = trail.arn
                        report.resource_tags = trail.tags
                        if trail.is_multiregion:
                            report.status_extended = (
                                f"Trail {trail.name} is multiregion and it is logging"
                            )
                        else:
                            report.status_extended = f"Trail {trail.name} is not multiregion and it is logging"
                        # Since there exists a logging trail in that region there is no point in checking the reamaining trails
                        # Store the finding and exit the loop
                        findings.append(report)
                        break
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            "No CloudTrail trails enabled and logging were found"
                        )
                        report.resource_arn = cloudtrail_client.audited_account_arn
                        report.resource_id = cloudtrail_client.audited_account
            # If there are no trails logging it is needed to store the FAIL once all the trails have been checked
            if report.status == "FAIL":
                findings.append(report)
        return findings
