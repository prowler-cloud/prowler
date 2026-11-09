from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)


class bedrockagentcore_token_vault_encrypted_with_cmk(Check):
    """Check whether Bedrock AgentCore token vaults use customer-managed KMS keys."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(
            bedrockagentcore_client.token_vaults_scan_errors.items()
        ):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "token-vault/unknown"
            report.resource_arn = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:token-vault/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock AgentCore token vault could not be retrieved in region {region} ({error}); verify access to GetTokenVault and manually confirm whether the vault uses a customer-managed KMS key."
            findings.append(report)

        for vault in bedrockagentcore_client.token_vaults.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=vault)
            if not vault.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} encryption configuration could not be retrieved in region {vault.region}; verify manually whether it uses a customer-managed KMS key."
            elif vault.kms_key_type == "CustomerManagedKey":
                report.status = "PASS"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} is encrypted with a customer-managed KMS key in region {vault.region}."
            elif vault.kms_key_type == "ServiceManagedKey":
                report.status = "FAIL"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} is encrypted with the default AWS-owned key instead of a customer-managed KMS key in region {vault.region}."
            else:
                report.status = "MANUAL"
                report.status_extended = f"Bedrock AgentCore token vault {vault.id} encryption key type is missing or unrecognized in region {vault.region}; verify manually whether it uses a customer-managed KMS key."
            findings.append(report)

        return findings
