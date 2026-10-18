from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_data_quality_job_intercontainer_encryption_enabled(Check):
    """Ensure SageMaker data quality job definition has inter-container traffic encryption enabled."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
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
