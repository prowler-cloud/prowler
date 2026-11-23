from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_imported_model_encrypted_with_cmk(Check):
    """Ensure Bedrock imported models use a customer-managed KMS key.

    - PASS: GetImportedModel returns a `modelKmsKeyArn`.
    - FAIL: No `modelKmsKeyArn` is set, so an AWS-owned key is in use.

    A model whose details GetImportedModel could not return produces no
    finding: its key is unknown, and the service already logged the error.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for model in bedrock_client.imported_models.values():
            if not model.detail_retrieved:
                continue
            report = Check_Report_AWS(metadata=self.metadata(), resource=model)
            if model.kms_key_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock imported model {model.name} is encrypted with a customer-managed KMS key in region {model.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock imported model {model.name} is not encrypted with a customer-managed KMS key in region {model.region}."
            findings.append(report)

        return findings
