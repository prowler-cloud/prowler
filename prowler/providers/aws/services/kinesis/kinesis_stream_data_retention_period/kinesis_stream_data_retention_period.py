from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kinesis.kinesis_client import kinesis_client


class kinesis_stream_data_retention_period(Check):
    def execute(self):
        findings = []
        for stream in kinesis_client.streams.values():
            report = Check_Report_AWS(self.metadata())
            report.region = stream.region
            report.resource_id = stream.name
            report.resource_arn = stream.arn
            report.resource_tags = stream.tags
            report.status = "FAIL"
            report.status_extended = f"Kinesis Stream {stream.name} does not have an adequate data retention period ({stream.retention_period}hrs)."

            if stream.retention_period <= kinesis_client.audit_config.get(
                "min_kinesis_stream_retention_period", 0
            ):
                report.status = "PASS"
                report.status_extended = f"Kinesis Stream {stream.name} does have an adequate data retention period ({stream.retention_period}hrs)."

            findings.append(report)

        return findings
