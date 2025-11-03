from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.firehose.firehose_client import firehose_client
from prowler.providers.aws.services.firehose.firehose_service import EncryptionStatus
from prowler.providers.aws.services.kafka.kafka_client import kafka_client
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
            report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled."

            if stream.kms_encryption == EncryptionStatus.ENABLED:
                report.status = "PASS"
                report.status_extended = f"Firehose Stream {stream.name} does have at rest encryption enabled."

            elif stream.delivery_stream_type == "KinesisStreamAsSource":
                source_stream_arn = stream.source.kinesis_stream.kinesis_stream_arn
                source_stream = kinesis_client.streams.get(source_stream_arn, None)
                if source_stream:
                    if source_stream.encrypted_at_rest == EncryptionType.KMS:
                        report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled even though source stream {source_stream.name} has at rest encryption enabled."
                    else:
                        report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled and the source stream {source_stream.name} is not encrypted at rest."
                else:
                    report.status_extended = f"Firehose Stream {stream.name} does not have at rest encryption enabled and the referenced source stream could not be found."

            elif stream.delivery_stream_type == "MSKAsSource":
                msk_cluster_arn = stream.source.msk.msk_cluster_arn
                msk_cluster = None
                if msk_cluster_arn:
                    for cluster in kafka_client.clusters.values():
                        if cluster.arn == msk_cluster_arn:
                            msk_cluster = cluster
                            break

                    if msk_cluster:
                        # All MSK clusters (both provisioned and serverless) always have encryption at rest enabled by AWS
                        # AWS MSK always encrypts data at rest - either with AWS managed keys or CMK
                        report.status = "PASS"
                        if msk_cluster.kafka_version == "SERVERLESS":
                            report.status_extended = f"Firehose Stream {stream.name} uses MSK serverless source which always has encryption at rest enabled by default."
                        else:
                            report.status_extended = f"Firehose Stream {stream.name} uses MSK provisioned source which always has encryption at rest enabled by AWS (either with AWS managed keys or CMK)."
                    else:
                        report.status_extended = f"Firehose Stream {stream.name} uses MSK source which always has encryption at rest enabled by AWS."

            findings.append(report)

        return findings
