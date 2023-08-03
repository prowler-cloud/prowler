from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Event_Selector


class cloudtrail_management_exist_with_multi_region_enabled(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.status = "FAIL"
        report.status_extended = (
            "No trail found with multi-region enabled and logging management events"
        )
        for trail in cloudtrail_client.trails:
            if trail.is_logging:
                if trail.is_multiregion:
                    for event in trail.data_events:
                        if type(event) is not Event_Selector:
                            continue
                        if event.event_selector.get(
                            "Name"
                        ) == "Management events selector" and all(
                            [
                                field["Field"] != "readOnly"
                                for field in event.event_selector["FieldSelectors"]
                            ]
                        ):
                            report = Check_Report_AWS(self.metadata())
                            report.region = trail.region
                            report.resource_id = trail.name
                            report.resource_arn = trail.arn
                            report.resource_tags = trail.tags
                            report.status = "PASS"
                            report.status_extended = f"Trail {trail.name} is multi-region, is logging and have management events logs enabled"
                            if report.resource_id not in [
                                f.resource_id for f in findings
                            ]:
                                findings.append(report)
                                break
        if len(findings) == 0:
            findings.append(report)
        return findings
