from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.firehose.firehose_client import firehose_client
from prowler.providers.aws.services.firehose.firehose_service import EncryptionStatus


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
            report.status = "PASS"
            report.status_extended = (
                f"Firehose Stream {stream.name} does have at rest encryption enabled."
            )

            # Check if the stream has encryption enabled directly
            has_direct_encryption = stream.kms_encryption == EncryptionStatus.ENABLED

            # Check if the stream has a Kinesis source with encryption enabled
            has_encrypted_kinesis_source = (
                stream.delivery_stream_type == "KinesisStreamAsSource"
                and stream.source_has_encryption
            )

            # Stream is considered encrypted if it has direct encryption OR encrypted source
            is_encrypted = has_direct_encryption or has_encrypted_kinesis_source

            if not is_encrypted:
                report.status = "FAIL"
                report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled."
            elif has_encrypted_kinesis_source and not has_direct_encryption:
                report.status_extended = f"Firehose Stream {stream.name} is encrypted through its Kinesis source stream."

            findings.append(report)

        return findings
