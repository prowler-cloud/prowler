from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kinesis.kinesis_client import kinesis_client
from prowler.providers.aws.services.kinesis.kinesis_service import EncryptionType


class kinesis_stream_encrypted_at_rest(Check):
    def execute(self):
        findings = []
        for stream in kinesis_client.streams.values():
            report = Check_Report_AWS(self.metadata())
            report.region = stream.region
            report.resource_id = stream.name
            report.resource_arn = stream.arn
            report.resource_tags = stream.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Kinesis Stream {stream.name} is not encrypted at rest."
            )

            if stream.encrypted_at_rest == EncryptionType.KMS:
                report.status = "PASS"
                report.status_extended = (
                    f"Kinesis Stream {stream.name} is encrypted at rest."
                )

            findings.append(report)

        return findings
