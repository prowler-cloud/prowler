from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_multi_region_enabled_logging_management_events(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No trail found with multi-region enabled and logging management events."
        )
        report.region = cloudtrail_client.region
        report.resource_id = cloudtrail_client.audited_account
        report.resource_arn = cloudtrail_client.trail_arn_template

        for trail in cloudtrail_client.trails:
            if trail.is_logging:
                if trail.is_multiregion:
                    for event in trail.data_events:
                        # Classic event selectors
                        if not event.is_advanced:
                            # Check if trail has IncludeManagementEvents and ReadWriteType is All
                            if (
                                event.event_selector["ReadWriteType"] == "All"
                                and event.event_selector["IncludeManagementEvents"]
                            ):
                                report.region = trail.region
                                report.resource_id = trail.name
                                report.resource_arn = trail.arn
                                report.resource_tags = trail.tags
                                report.status = "PASS"
                                report.status_extended = f"Trail {trail.name} from home region {trail.home_region} is multi-region, is logging and have management events enabled."

                        # Advanced event selectors
                        elif event.is_advanced:
                            if event.event_selector.get(
                                "Name"
                            ) == "Management events selector" and all(
                                [
                                    field["Field"] != "readOnly"
                                    for field in event.event_selector["FieldSelectors"]
                                ]
                            ):
                                report.region = trail.region
                                report.resource_id = trail.name
                                report.resource_arn = trail.arn
                                report.resource_tags = trail.tags
                                report.status = "PASS"
                                report.status_extended = f"Trail {trail.name} from home region {trail.home_region} is multi-region, is logging and have management events enabled."
        findings.append(report)
        return findings
