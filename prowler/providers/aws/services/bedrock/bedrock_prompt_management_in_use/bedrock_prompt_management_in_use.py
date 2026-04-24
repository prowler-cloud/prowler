"""Check for region-level Bedrock Prompt Management adoption."""

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_prompt_management_in_use(Check):
    """Check whether Amazon Bedrock Prompt Management is in use in the region.

    A region is reported only when ListPrompts succeeded for it; regions where
    the API call failed (e.g. AccessDenied, unsupported region) are skipped at
    the service layer and produce no finding.

    - PASS: At least one managed prompt exists in the region.
    - FAIL: No managed prompts exist in the region.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock Prompt Management in use check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region in sorted(bedrock_agent_client.prompt_scanned_regions):
            report = Check_Report_AWS(metadata=self.metadata(), resource={})
            report.region = region
            report.resource_id = "prompt-management"
            report.resource_arn = f"arn:{bedrock_agent_client.audited_partition}:bedrock:{region}:{bedrock_agent_client.audited_account}:prompt-management"
            report.status = "FAIL"
            report.status_extended = (
                f"Bedrock Prompt Management is not in use in region {region}."
            )

            region_prompts = [
                prompt
                for prompt in bedrock_agent_client.prompts.values()
                if prompt.region == region
            ]
            if region_prompts:
                report.status = "PASS"
                report.status_extended = f"Bedrock Prompt Management is in use with {len(region_prompts)} prompt(s) in region {region}."

            findings.append(report)

        return findings
