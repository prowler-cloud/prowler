from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_clarify_exists(Check):
    """Check whether at least one SageMaker Clarify processing job exists per region.

    A region is reported only when ListProcessingJobs succeeded for it; regions
    where the API call failed (e.g. AccessDenied, unsupported region) are
    skipped at the service layer and produce no finding.

    - PASS: At least one processing job uses the AWS-managed Clarify container
      image in the region (one finding per job).
    - FAIL: No processing job uses the Clarify container image in the region
      (one finding per region).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the SageMaker Clarify exists check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region in sorted(sagemaker_client.processing_jobs_scanned_regions):
            clarify_jobs = sorted(
                (
                    job
                    for job in sagemaker_client.sagemaker_processing_jobs
                    if job.region == region
                    and job.image_uri
                    and "sagemaker-clarify-processing" in job.image_uri
                ),
                key=lambda job: job.name,
            )

            if clarify_jobs:
                for job in clarify_jobs:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=job)
                    report.status = "PASS"
                    report.status_extended = f"SageMaker Clarify processing job {job.name} exists in region {region}."
                    findings.append(report)
            else:
                report = Check_Report_AWS(metadata=self.metadata(), resource={})
                report.region = region
                report.resource_id = "sagemaker-clarify"
                report.resource_arn = f"arn:{sagemaker_client.audited_partition}:sagemaker:{region}:{sagemaker_client.audited_account}:processing-job"
                report.status = "FAIL"
                report.status_extended = (
                    f"No SageMaker Clarify processing jobs found in region {region}."
                )
                findings.append(report)

        return findings
