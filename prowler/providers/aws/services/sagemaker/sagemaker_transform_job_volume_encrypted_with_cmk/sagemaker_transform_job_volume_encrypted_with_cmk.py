from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_transform_job_volume_encrypted_with_cmk(Check):
    """Ensure SageMaker transform job volumes use a customer-managed KMS key.

    Batch transform jobs write intermediate data to an attached ML storage
    volume. When ``TransformResources.VolumeKmsKeyId`` is unset, SageMaker
    encrypts the volume with a transient key and discards it after encryption
    (not an AWS-managed KMS key). That transient key cannot carry a custom key
    policy, so rotation, access and lifecycle remain outside the account
    owner's control.

    - PASS: ``VolumeKmsKeyId`` is present on the transform job.
    - FAIL: ``VolumeKmsKeyId`` is absent after a successful describe.
    - MANUAL: ``DescribeTransformJob`` failed, or ``ListTransformJobs`` failed
      for a region, so encryption cannot be determined either way.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the SageMaker transform job volume CMK encryption check.

        Returns:
            One report per transform job in the inventory, plus one MANUAL
            report per region where ``ListTransformJobs`` failed.
        """
        findings = []

        # Distinguishes a failed ListTransformJobs call from a genuinely empty
        # inventory: failed regions must not silently produce zero findings.
        for region in sorted(sagemaker_client.transform_jobs_list_failed_regions):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = region
            report.resource_id = "sagemaker-transform-jobs"
            report.resource_arn = (
                f"arn:{sagemaker_client.audited_partition}:sagemaker:{region}:"
                f"{sagemaker_client.audited_account}:transform-job"
            )
            report.status = "MANUAL"
            report.status_extended = (
                f"SageMaker transform job inventory could not be listed in "
                f"region {region}; volume encryption cannot be verified."
            )
            findings.append(report)

        for transform_job in sagemaker_client.sagemaker_transform_jobs:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=transform_job
            )
            if transform_job.detail_fetch_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} details could "
                    f"not be described ({transform_job.detail_fetch_error}); "
                    "volume encryption cannot be verified."
                )
            elif transform_job.volume_kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} encrypts its "
                    f"volume with the customer-managed KMS key "
                    f"{transform_job.volume_kms_key_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker transform job {transform_job.name} does not "
                    "encrypt its volume with a customer-managed KMS key."
                )
            findings.append(report)
        return findings
