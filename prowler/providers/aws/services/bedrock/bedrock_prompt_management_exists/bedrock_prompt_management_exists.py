"""Check for region-level Bedrock Prompt Management adoption."""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_prompt_management_exists(Check):
    """Check whether Amazon Bedrock Prompt Management prompts exist in the region.

    A region is reported only when ListPrompts succeeded for it; regions where
    the API call failed (e.g. AccessDenied, unsupported region) are skipped at
    the service layer and produce no finding.

    - PASS: At least one managed prompt exists in the region (one finding per prompt).
    - FAIL: No managed prompts exist in the region (one finding per region).
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock Prompt Management exists check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region in sorted(bedrock_agent_client.prompt_scanned_regions):
            regional_prompts = sorted(
                (
                    prompt
                    for prompt in bedrock_agent_client.prompts.values()
                    if prompt.region == region
                ),
                key=lambda prompt: prompt.name,
            )

            if regional_prompts:
                for prompt in regional_prompts:
                    report = Check_Report_AWS(metadata=self.metadata(), resource=prompt)
                    report.status = "PASS"
                    report.status_extended = f"Bedrock Prompt Management prompt {prompt.name} exists in region {region}."
                    findings.append(report)
            else:
                report = Check_Report_AWS(metadata=self.metadata(), resource={})
                report.region = region
                report.resource_id = "prompt-management"
                report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:prompt-management"
                report.status = "FAIL"
                report.status_extended = (
                    f"No Bedrock Prompt Management prompts exist in region {region}."
                )
                findings.append(report)

        return findings
