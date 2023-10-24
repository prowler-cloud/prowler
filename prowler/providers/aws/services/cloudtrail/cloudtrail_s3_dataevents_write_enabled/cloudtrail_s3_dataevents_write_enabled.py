from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.s3.s3_client import s3_client


class cloudtrail_s3_dataevents_write_enabled(Check):
    def execute(self):
        findings = []
        for trail in cloudtrail_client.trails:
            for data_event in trail.data_events:
                # Classic event selectors
                if not data_event.is_advanced:
                    # Check if trail has a data event for all S3 Buckets for write
                    if (
                        data_event.event_selector["ReadWriteType"] == "All"
                        or data_event.event_selector["ReadWriteType"] == "WriteOnly"
                    ):
                        for resource in data_event.event_selector["DataResources"]:
                            if "AWS::S3::Object" == resource["Type"] and (
                                f"arn:{cloudtrail_client.audited_partition}:s3"
                                in resource["Values"]
                                or f"arn:{cloudtrail_client.audited_partition}:s3:::"
                                in resource["Values"]
                                or f"arn:{cloudtrail_client.audited_partition}:s3:::*/*"
                                in resource["Values"]
                            ):
                                report = Check_Report_AWS(self.metadata())
                                report.region = trail.region
                                report.resource_id = trail.name
                                report.resource_arn = trail.arn
                                report.resource_tags = trail.tags
                                report.status = "PASS"
                                report.status_extended = f"Trail {trail.name} from home region {trail.home_region} has a classic data event selector to record all S3 object-level API operations."
                                findings.append(report)
                # Advanced event selectors
                elif data_event.is_advanced:
                    for field_selector in data_event.event_selector["FieldSelectors"]:
                        if (
                            field_selector["Field"] == "resources.type"
                            and field_selector["Equals"][0] == "AWS::S3::Object"
                        ):
                            report = Check_Report_AWS(self.metadata())
                            report.region = trail.region
                            report.resource_id = trail.name
                            report.resource_arn = trail.arn
                            report.resource_tags = trail.tags
                            report.status = "PASS"
                            report.status_extended = f"Trail {trail.name} from home region {trail.home_region} has an advanced data event selector to record all S3 object-level API operations."
                            findings.append(report)
        if not findings and (
            s3_client.buckets or not cloudtrail_client.audit_info.reduce_noise
        ):
            report = Check_Report_AWS(self.metadata())
            report.region = cloudtrail_client.region
            report.resource_arn = cloudtrail_client.audited_account_arn
            report.resource_id = cloudtrail_client.audited_account
            report.status = "FAIL"
            report.status_extended = "No CloudTrail trails have a data event to record all S3 object-level API operations."
            findings.append(report)
        return findings
