from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_multi_region_enabled_logging_management_events(Check):
    def execute(self):
        findings = []
        if cloudtrail_client.trails is not None:
            for region in cloudtrail_client.regional_clients.keys():
                report = Check_Report_AWS(self.metadata())
                report.status = "FAIL"
                report.status_extended = "No CloudTrail trails enabled and logging management events were found."
                report.region = region
                report.resource_id = cloudtrail_client.audited_account
                report.resource_arn = cloudtrail_client._get_trail_arn_template(region)
                trail_is_logging_management_events = False
                for trail in cloudtrail_client.trails.values():
                    if trail.region == region or trail.is_multiregion:
                        if trail.is_logging:
                            for event in trail.data_events:
                                # Classic event selectors
                                if not event.is_advanced:
                                    # Check if trail has IncludeManagementEvents and ReadWriteType is All
                                    if (
                                        event.event_selector["ReadWriteType"] == "All"
                                        and event.event_selector[
                                            "IncludeManagementEvents"
                                        ]
                                    ):
                                        trail_is_logging_management_events = True

                                # Advanced event selectors
                                elif event.is_advanced:
                                    if event.event_selector.get(
                                        "Name"
                                    ) == "Management events selector" and all(
                                        [
                                            field["Field"] != "readOnly"
                                            for field in event.event_selector[
                                                "FieldSelectors"
                                            ]
                                        ]
                                    ):
                                        trail_is_logging_management_events = True
                    if trail_is_logging_management_events:
                        report.resource_id = trail.name
                        report.resource_arn = trail.arn
                        report.resource_tags = trail.tags
                        report.region = region
                        report.status = "PASS"
                        if trail.is_multiregion:
                            report.status_extended = f"Trail {trail.name} from home region {trail.home_region} is multi-region, is logging and have management events enabled."
                        else:
                            report.status_extended = f"Trail {trail.name} in region {trail.home_region} is logging and have management events enabled."
                        # Since there exists a logging trail in that region there is no point in checking the remaining trails
                        # Store the finding and exit the loop
                        findings.append(report)
                        break
                if report.status == "FAIL":
                    findings.append(report)
        return findings
