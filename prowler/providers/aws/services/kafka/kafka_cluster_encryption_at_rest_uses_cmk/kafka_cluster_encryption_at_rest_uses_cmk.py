from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.kafka.kafka_client import kafka_client
from prowler.providers.aws.services.kms.kms_client import kms_client


class kafka_cluster_encryption_at_rest_uses_cmk(Check):
    """Ensure Amazon MSK clusters use a customer-managed KMS key at rest."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Amazon MSK encryption-at-rest check.

        Returns:
            list[Check_Report_AWS]: Reports for Amazon MSK clusters, including
            manual results when KMS evidence is incomplete.
        """
        findings = []
        kms_scan_errors = getattr(kms_client, "keys_scan_errors", {})
        if not isinstance(kms_scan_errors, dict):
            kms_scan_errors = {}

        for cluster in kafka_client.clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=cluster)
            report.status = "FAIL"
            report.status_extended = f"Kafka cluster '{cluster.name}' does not have encryption at rest enabled with a CMK."

            # Serverless clusters always have encryption at rest enabled by default
            if cluster.kafka_version == "SERVERLESS":
                report.status = "PASS"
                report.status_extended = f"Kafka cluster '{cluster.name}' is serverless and always has encryption at rest enabled by default."
            else:
                matching_key = next(
                    (
                        key
                        for key in kms_client.keys
                        if cluster.data_volume_kms_key_id == key.arn
                    ),
                    None,
                )
                if cluster.region in kms_scan_errors:
                    error = kms_scan_errors[cluster.region]
                    report.status = "MANUAL"
                    report.status_extended = f"KMS keys could not be listed in region {cluster.region} ({error}), so encryption at rest for Kafka cluster '{cluster.name}' cannot be verified."
                elif matching_key is not None and not getattr(
                    matching_key, "detail_retrieved", False
                ):
                    error = (
                        getattr(matching_key, "detail_fetch_error", None)
                        or "UnknownError"
                    )
                    report.status = "MANUAL"
                    report.status_extended = f"KMS key {matching_key.arn} could not be described in region {cluster.region} ({error}), so encryption at rest for Kafka cluster '{cluster.name}' cannot be verified."
                elif matching_key is not None and matching_key.manager == "CUSTOMER":
                    report.status = "PASS"
                    report.status_extended = f"Kafka cluster '{cluster.name}' has encryption at rest enabled with a CMK."

            findings.append(report)

        return findings
