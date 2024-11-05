from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.firehose.firehose_client import firehose_client
from prowler.providers.aws.services.firehose.firehose_service import EncryptionStatus


class firehose_stream_encrypted_at_rest(Check):
    def execute(self):
        findings = []
        for stream in firehose_client.delivery_streams.values():
            report = Check_Report_AWS(self.metadata())
            report.region = stream.region
            report.resource_id = stream.name
            report.resource_arn = stream.arn
            report.resource_tags = stream.tags
            report.status = "PASS"
            report.status_extended = (
                f"Firehose Stream {stream.name} does have at rest encryption enabled."
            )

            if (
                stream.kms_encryption != EncryptionStatus.ENABLED
                or not stream.kms_key_arn
            ):
                report.status = "FAIL"
                report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled."

            findings.append(report)

        return findings
