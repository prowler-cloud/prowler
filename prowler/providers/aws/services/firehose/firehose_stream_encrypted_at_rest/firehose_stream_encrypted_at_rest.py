from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.firehose.firehose_client import firehose_client
from prowler.providers.aws.services.firehose.firehose_service import EncryptionStatus
from prowler.providers.aws.services.kinesis.kinesis_client import kinesis_client
from prowler.providers.aws.services.kinesis.kinesis_service import EncryptionType


class firehose_stream_encrypted_at_rest(Check):
    """Check if Firehose Streams are encrypted at rest.

    This class verifies that all Firehose Streams have at rest encryption enabled by checking if KMS encryption is active and a KMS Key is configured.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the Firehose Stream Encrypted at Rest check.

        Iterates over all Firehose Streams and checks if KMS encryption is enabled and a KMS Key is configured.

        Returns:
            List[Check_Report_AWS]: A list of reports for each Firehose Stream.
        """
        findings = []
        for stream in firehose_client.delivery_streams.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=stream)
            report.status = "FAIL"
            report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled or the source stream is not encrypted."

            # Encrypted Kinesis Stream source
            if stream.delivery_stream_type == "KinesisStreamAsSource":
                source_stream = kinesis_client.streams.get(
                    stream.source.kinesis_stream.kinesis_stream_arn
                )
                if source_stream.encrypted_at_rest != EncryptionType.NONE:
                    report.status = "PASS"
                    report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled but the source stream {source_stream.name} has at rest encryption enabled."

            # Check if the stream has encryption enabled directly
            elif stream.kms_encryption == EncryptionStatus.ENABLED:
                report.status = "PASS"
                report.status_extended = f"Firehose Stream {stream.name} does have at rest encryption enabled."

            findings.append(report)

        return findings
