from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kinesis.kinesis_client import kinesis_client


class kinesis_stream_data_retention_period(Check):
    """Ensure Kinesis Stream has an adequate data retention period

    The retention period for Kinesis Streams should be set to a value that meets the organization's data retention policy.
    """

    def execute(self):
        """Execute Check Kinesis Stream data retention period

        Iterate over all Kinesis Streams and check if the retention period is adequate.

        Returns:
            findings (list): List of findings
        """
        findings = []
        for stream in kinesis_client.streams.values():
            report = Check_Report_AWS(self.metadata())
            report.region = stream.region
            report.resource_id = stream.name
            report.resource_arn = stream.arn
            report.resource_tags = stream.tags
            report.status = "FAIL"
            report.status_extended = f"Kinesis Stream {stream.name} does not have an adequate data retention period ({stream.retention_period}hrs)."

            if stream.retention_period >= kinesis_client.audit_config.get(
                "min_kinesis_stream_retention_hours", 168
            ):
                report.status = "PASS"
                report.status_extended = f"Kinesis Stream {stream.name} does have an adequate data retention period ({stream.retention_period}hrs)."

            findings.append(report)

        return findings
