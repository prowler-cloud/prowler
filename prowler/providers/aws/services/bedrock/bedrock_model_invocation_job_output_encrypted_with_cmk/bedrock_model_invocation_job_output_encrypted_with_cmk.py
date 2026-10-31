from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import (
    bedrock_client,
)


class bedrock_model_invocation_job_output_encrypted_with_cmk(Check):
    """Ensure Bedrock model invocation job outputs use a customer-managed KMS
    key."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # If listing model invocation jobs failed in a region,
        # we cannot determine the encryption status of jobs in that region.
        for region, error in sorted(
            bedrock_client.model_invocation_jobs_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={"region": region},
            )
            report.region = region
            report.resource_id = "model-invocation-job/unknown"
            report.resource_arn = (
                f"arn:{bedrock_client.audited_partition}:bedrock:"
                f"{region}:{bedrock_client.audited_account}:"
                "model-invocation-job/unknown"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"Bedrock model invocation jobs could not be listed in region "
                f"{region} ({error}); verify manually that every model "
                "invocation job output uses a customer-managed KMS key."
            )
            findings.append(report)

        # Evaluate each discovered model invocation job.
        for job in bedrock_client.model_invocation_jobs.values():
            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource=job,
            )

            # If GetModelInvocationJob failed, the encryption configuration
            # cannot be determined. Never report PASS in this situation.
            if not job.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock model invocation job {job.name} "
                    f"output encryption configuration could not be "
                    f"retrieved in region {job.region}; verify manually "
                    "that the S3 output uses a customer-managed KMS key."
                )

            # A present s3EncryptionKeyId indicates that the S3 output
            # configuration specifies a KMS encryption key.
            elif job.s3_encryption_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock model invocation job {job.name} S3 output "
                    f"is configured with a customer-managed KMS key in "
                    f"region {job.region}."
                )

            # Missing or empty s3EncryptionKeyId means the required
            # customer-managed KMS key is not configured.
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock model invocation job {job.name} S3 output "
                    f"is not configured with a customer-managed KMS key "
                    f"in region {job.region}."
                )

            findings.append(report)

        return findings
