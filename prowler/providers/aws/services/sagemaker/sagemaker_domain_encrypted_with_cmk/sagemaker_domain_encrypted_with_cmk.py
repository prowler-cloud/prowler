from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_domain_encrypted_with_cmk(Check):
    """Ensure SageMaker domains encrypt their volumes with a customer-managed KMS key.

    A SageMaker Domain stores notebooks and user data on EFS and EBS volumes.
    When ``KmsKeyId`` is unset the domain falls back to the AWS managed key,
    which cannot carry a custom key policy and whose rotation, access and
    lifecycle are outside the account owner's control.

    - PASS: The domain has a ``KmsKeyId`` set.
    - FAIL: The domain has no ``KmsKeyId`` and therefore uses the AWS managed key.
    - MANUAL: The domain details could not be described, so encryption cannot
      be determined either way.
    """

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        for domain in sagemaker_client.sagemaker_domains:
            report = Check_Report_AWS(metadata=self.metadata(), resource=domain)
            if domain.detail_fetch_error:
                report.status = "MANUAL"
                report.status_extended = f"SageMaker domain {domain.name} details could not be described ({domain.detail_fetch_error}); volume encryption cannot be verified."
            elif domain.kms_key_id:
                report.status = "PASS"
                report.status_extended = f"SageMaker domain {domain.name} encrypts its EFS and EBS volumes with the customer-managed KMS key {domain.kms_key_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker domain {domain.name} does not encrypt its EFS and EBS volumes with a customer-managed KMS key."

            findings.append(report)

        return findings
