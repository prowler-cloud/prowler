from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_data_quality_job_intercontainer_encryption_enabled(Check):
    """Ensure SageMaker data quality job definition has inter-container traffic encryption enabled."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for (
            region,
            error_code,
        ) in sagemaker_client.data_quality_job_definitions_scan_errors.items():
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.status = "MANUAL"
            report.status_extended = f"SageMaker data quality job definitions could not be listed in region {region} due to {error_code}."
            report.region = region
            report.resource_id = sagemaker_client.audited_account
            report.resource_arn = f"arn:{sagemaker_client.audited_partition}:sagemaker:{region}:{sagemaker_client.audited_account}:data-quality-job-definition"
            findings.append(report)

        for job_def in sagemaker_client.data_quality_job_definitions:
            report = Check_Report_AWS(metadata=self.metadata(), resource=job_def)
            if not job_def.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker data quality job definition {job_def.name} "
                    f"details could not be retrieved."
                )
            elif job_def.enable_inter_container_traffic_encryption:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker data quality job definition {job_def.name} "
                    f"has inter-container traffic encryption enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker data quality job definition {job_def.name} "
                    f"has inter-container traffic encryption disabled."
                )

            findings.append(report)

        return findings
