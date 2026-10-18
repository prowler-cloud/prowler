from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_hyperparameter_tuning_job_volume_encrypted_with_cmk(Check):
    """Ensure that Amazon SageMaker hyperparameter tuning jobs have storage volume encrypted with KMS CMK.

    This check evaluates whether each SageMaker hyperparameter tuning job encrypts its
    storage volume using a customer-managed KMS key.
    - PASS: The SageMaker hyperparameter tuning job storage volume is encrypted with a KMS CMK.
    - FAIL: The SageMaker hyperparameter tuning job storage volume is not encrypted with a KMS CMK.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the SageMaker hyperparameter tuning job CMK volume encryption check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for tuning_job in sagemaker_client.sagemaker_hyperparameter_tuning_jobs:
            report = Check_Report_AWS(metadata=self.metadata(), resource=tuning_job)
            if tuning_job.all_definitions_encrypted:
                report.status = "PASS"
                report.status_extended = f"SageMaker hyperparameter tuning job {tuning_job.name} has storage volume encrypted with KMS CMK."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker hyperparameter tuning job {tuning_job.name} does not have storage volume encrypted with KMS CMK."
            findings.append(report)

        return findings
