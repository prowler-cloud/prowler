from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.kms.kms_client import kms_client


class ecr_repository_encrypted_with_cmk(Check):
    """Check if ECR repositories are encrypted with a customer-managed KMS key.

    - PASS: The repository uses KMS encryption and the associated key is
      confirmed to be customer-managed.
    - FAIL: The repository uses AES256 encryption, has no KMS key configured,
      or the KMS key is confirmed to be AWS-managed.
    - MANUAL: The repository uses KMS encryption but the associated key could
      not be found in the KMS inventory, so the key manager cannot be
      determined. This may occur when KMS key collection encountered errors.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the ECR repository CMK encryption check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
                report.status = "FAIL"
                report.status_extended = f"Repository {repository.name} does not have KMS encryption configured with a customer-managed key."

                if repository.encryption_type == "KMS" and repository.kms_key:
                    key_found = False
                    for key in kms_client.keys:
                        if (
                            key.arn == repository.kms_key
                            or key.id == repository.kms_key
                        ):
                            key_found = True
                            if getattr(key, "manager", "") == "CUSTOMER":
                                report.status = "PASS"
                                report.status_extended = f"Repository {repository.name} has KMS encryption configured with a customer-managed key."
                            break

                    if not key_found:
                        report.status = "MANUAL"
                        report.status_extended = f"Repository {repository.name} uses KMS encryption but the key {repository.kms_key} could not be found in the KMS inventory; verify manually that it is a customer-managed key."

                findings.append(report)

        return findings
