from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_imported_model_encrypted_with_cmk(Check):
    """Ensure Bedrock imported models use a customer-managed KMS key."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(bedrock_client.imported_models_scan_errors.items()):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "imported-model/unknown"
            report.resource_arn = f"arn:{bedrock_client.audited_partition}:bedrock:{region}:{bedrock_client.audited_account}:imported-model/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock imported models could not be listed in region {region} ({error}); verify manually that every imported model uses a customer-managed KMS key."
            findings.append(report)

        for model in bedrock_client.imported_models.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=model)
            if not model.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock imported model {model.name} encryption configuration could not be retrieved in region {model.region}; verify manually that it uses a customer-managed KMS key."
            elif model.kms_key_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock imported model {model.name} is encrypted with a customer-managed KMS key in region {model.region}."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock imported model {model.name} is not encrypted with a customer-managed KMS key in region {model.region}."
            findings.append(report)

        return findings
