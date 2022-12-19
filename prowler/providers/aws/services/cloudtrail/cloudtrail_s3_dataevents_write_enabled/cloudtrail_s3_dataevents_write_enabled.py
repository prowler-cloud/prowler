from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)


class cloudtrail_s3_dataevents_write_enabled(Check):
    def execute(self):
        findings = []
        report = Check_Report_AWS(self.metadata())
        report.region = cloudtrail_client.region
        report.resource_id = "No trails"
        report.resource_arn = "No trails"
        report.status = "FAIL"
        report.status_extended = "No CloudTrail trails have a data event to record all S3 object-level API operations."
        for trail in cloudtrail_client.trails:
            for data_event in trail.data_events:
                # Check if trail has a data event for all S3 Buckets for write
                if (
                    data_event["ReadWriteType"] == "All"
                    or data_event["ReadWriteType"] == "WriteOnly"
                ):
                    for resource in data_event["DataResources"]:
                        if "AWS::S3::Object" == resource["Type"] and (
                            "arn:aws:s3" in resource["Values"]
                            or "arn:aws:s3:::*/*" in resource["Values"]
                        ):
                            report.region = trail.region
                            report.resource_id = trail.name
                            report.resource_arn = trail.arn
                            report.status = "PASS"
                            report.status_extended = f"Trail {trail.name} have a data event to record all S3 object-level API operations."

        findings.append(report)
        return findings
