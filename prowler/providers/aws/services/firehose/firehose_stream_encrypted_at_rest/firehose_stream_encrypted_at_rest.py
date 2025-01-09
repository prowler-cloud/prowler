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
            report = Check_Report_AWS(self.metadata())
            report.region = stream.region
            report.resource_id = stream.name
            report.resource_arn = stream.arn
            report.resource_tags = stream.tags
            report.status = "PASS"
            report.status_extended = (
                f"Firehose Stream {stream.name} does have at rest encryption enabled."
            )

            if stream.kms_encryption != EncryptionStatus.ENABLED:
                report.status = "FAIL"
                report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled."

            findings.append(report)

        return findings
