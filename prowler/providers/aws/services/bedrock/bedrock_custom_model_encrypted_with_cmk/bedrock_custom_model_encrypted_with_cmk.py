from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_custom_model_encrypted_with_cmk(Check):
    """Ensure Bedrock custom models are encrypted with a customer-managed KMS key.

    - PASS: GetCustomModel returns a `modelKmsKeyArn`, so the model artifacts
      are encrypted with a key the account controls.
    - FAIL: No `modelKmsKeyArn` is set, so the model is encrypted with an
      AWS-owned key that the organization cannot audit, rotate, or revoke.
    - MANUAL: GetCustomModel failed, so the key could not be retrieved and an
      absent value cannot be read as "no key"; or ListCustomModels failed for a
      region, so that region's custom models are unknown rather than absent.

    Only models this account owns are audited (`ListCustomModels` is called with
    `isOwned=True`): the KMS key of a model shared in through Resource Access
    Manager belongs to the owning account and cannot be changed here.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(bedrock_client.custom_models_scan_errors.items()):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "custom-model/unknown"
            report.resource_arn = f"arn:{bedrock_client.audited_partition}:bedrock:{region}:{bedrock_client.audited_account}:custom-model/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock custom models could not be listed in region {region} ({error}); verify manually that every custom model uses a customer-managed KMS key."
            findings.append(report)

        for model in bedrock_client.custom_models.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=model)

            if not model.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock custom model {model.name} encryption configuration could not be retrieved in region {model.region}; verify manually that it uses a customer-managed KMS key."
            elif model.kms_key_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock custom model {model.name} is encrypted with a customer-managed KMS key in region {model.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock custom model {model.name} is not encrypted with a customer-managed KMS key in region {model.region}, so the fine-tuned weights rest under an AWS-owned key the organization cannot audit or revoke."
            findings.append(report)

        return findings
