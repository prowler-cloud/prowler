from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecr.ecr_client import ecr_client
from prowler.providers.aws.services.kms.kms_client import kms_client

# ECR accepts AES256, KMS and KMS_DSSE. Both KMS modes can be backed by a
# customer-managed key, KMS_DSSE adding a second layer of encryption on top.
CMK_CAPABLE_ENCRYPTION_TYPES = ("KMS", "KMS_DSSE")


class ecr_repository_encrypted_with_cmk(Check):
    """Check if ECR repositories are encrypted with a customer-managed KMS key.

    - PASS: The repository uses KMS or KMS_DSSE encryption and the associated
      key is confirmed to be customer-managed.
    - FAIL: The repository uses AES256 encryption, has no KMS key configured,
      or the KMS key is confirmed to be AWS-managed.
    - MANUAL: The repository uses KMS encryption but the manager of the
      associated key cannot be determined, either because the key is missing
      from the KMS inventory or because DescribeKey did not return for it. An
      unreadable key cannot be reported as "not customer-managed".
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the ECR repository CMK encryption check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        # Resolved once: a repository key is matched by ARN, and by key ID for
        # the rare configuration that stores the bare identifier.
        key_managers = {}
        for key in kms_client.keys:
            key_managers[key.arn] = key.manager
            key_managers[key.id] = key.manager

        for registry in ecr_client.registries.values():
            for repository in registry.repositories:
                report = Check_Report_AWS(metadata=self.metadata(), resource=repository)
                report.status = "FAIL"
                report.status_extended = f"Repository {repository.name} does not have KMS encryption configured with a customer-managed key."

                if (
                    repository.encryption_type in CMK_CAPABLE_ENCRYPTION_TYPES
                    and repository.kms_key
                ):
                    # None covers both a key absent from the inventory and a key
                    # whose DescribeKey call failed, neither of which supports a
                    # FAIL.
                    key_manager = key_managers.get(repository.kms_key)

                    if key_manager == "CUSTOMER":
                        report.status = "PASS"
                        report.status_extended = f"Repository {repository.name} has KMS encryption configured with a customer-managed key."
                    elif key_manager is None:
                        report.status = "MANUAL"
                        report.status_extended = f"Repository {repository.name} uses KMS encryption but the manager of key {repository.kms_key} could not be determined from the KMS inventory; verify manually that it is a customer-managed key."

                findings.append(report)

        return findings
