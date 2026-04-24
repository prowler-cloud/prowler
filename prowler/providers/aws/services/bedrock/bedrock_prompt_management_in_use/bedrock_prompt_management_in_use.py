"""Check for Bedrock Prompt Management utilization."""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_prompt_management_in_use(Check):
    """Ensure that Bedrock Prompt Management is utilized for centralized prompt governance.

    This check verifies whether Amazon Bedrock Prompt Management is in use
    by checking for the existence of managed prompts in each region.
    - PASS: At least one managed prompt exists in the region.
    - FAIL: No managed prompts exist in the region.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock Prompt Management in use check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region in bedrock_agent_client.regional_clients:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={}
            )
            report.region = region
            report.resource_id = "prompt-management"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:prompt-management"
            report.status = "FAIL"
            report.status_extended = (
                "Bedrock Prompt Management is not in use in this region."
            )

            region_prompts = [
                prompt
                for prompt in bedrock_agent_client.prompts.values()
                if prompt.region == region
            ]
            if region_prompts:
                report.status = "PASS"
                report.status_extended = f"Bedrock Prompt Management is in use with {len(region_prompts)} prompt(s) in this region."

            findings.append(report)

        return findings
