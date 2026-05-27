from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_prompt_encrypted_with_cmk(Check):
    """Ensure that Bedrock prompts are encrypted with a customer-managed KMS key.

    This check evaluates whether each Bedrock prompt is encrypted at rest using
    a customer-managed KMS key (CMK) rather than the AWS-owned default key.
    - PASS: The Bedrock prompt is encrypted with a customer-managed KMS key.
    - FAIL: The Bedrock prompt is not encrypted with a customer-managed KMS key.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock prompt CMK encryption check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for prompt in bedrock_agent_client.prompts.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=prompt)
            if prompt.customer_encryption_key_arn:
                report.status = "PASS"
                report.status_extended = f"Bedrock Prompt {prompt.name} is encrypted with a customer-managed KMS key."
            else:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Prompt {prompt.name} is not encrypted with a customer-managed KMS key."
            findings.append(report)
        return findings
