import re

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
        audit_resources = bedrockagentcore_client.audit_resources

        for region, error in sorted(
            bedrockagentcore_client.token_vaults_scan_errors.items()
        ):
            # A failed read has no vault ID, so with selected resources the error stays
            # in scope only if a selected ARN names a vault in this Region with a valid
            # tokenVaultId (1-64 characters of [a-zA-Z0-9-_]).
            vault_prefix = f"arn:{bedrockagentcore_client.audited_partition}:bedrock-agentcore:{region}:{bedrockagentcore_client.audited_account}:token-vault/"
            if audit_resources and not any(
                arn.startswith(vault_prefix)
                and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", arn[len(vault_prefix) :])
                for arn in audit_resources
            ):
                continue
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
