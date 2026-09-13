from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_processing_job_volume_encrypted_with_cmk(Check):
    """Ensure SageMaker processing job volumes use a customer-managed KMS key.

    Processing jobs write intermediate data to an attached ML storage volume.
    When ``ProcessingResources.ClusterConfig.VolumeKmsKeyId`` is unset the
    volume falls back to an AWS-managed key, which cannot carry a custom key
    policy and whose rotation, access and lifecycle are outside the account
    owner's control.

    - PASS: ``VolumeKmsKeyId`` is present on the processing job.
    - FAIL: ``VolumeKmsKeyId`` is absent after a successful describe.
    - MANUAL: ``DescribeProcessingJob`` failed, or ``ListProcessingJobs`` failed
      for a region, so encryption cannot be determined either way.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the SageMaker processing job volume CMK encryption check.

        Returns:
            One report per processing job in the inventory, plus one MANUAL
            report per region where ``ListProcessingJobs`` failed.
        """
        findings = []

        # Distinguishes a failed ListProcessingJobs call from a genuinely empty
        # inventory: failed regions must not silently produce zero findings.
        for region in sorted(sagemaker_client.processing_jobs_list_failed_regions):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = region
            report.resource_id = "sagemaker-processing-jobs"
            report.resource_arn = (
                f"arn:{sagemaker_client.audited_partition}:sagemaker:{region}:"
                f"{sagemaker_client.audited_account}:processing-job"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"SageMaker processing job inventory could not be listed in "
                f"region {region}; volume encryption cannot be verified."
            )
            findings.append(report)

        for processing_job in sagemaker_client.sagemaker_processing_jobs:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=processing_job
            )
            if processing_job.detail_fetch_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker processing job {processing_job.name} details could "
                    f"not be described ({processing_job.detail_fetch_error}); "
                    "volume encryption cannot be verified."
                )
            elif processing_job.volume_kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker processing job {processing_job.name} encrypts its "
                    f"volume with the customer-managed KMS key "
                    f"{processing_job.volume_kms_key_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker processing job {processing_job.name} does not "
                    "encrypt its volume with a customer-managed KMS key."
                )
            findings.append(report)
        return findings
