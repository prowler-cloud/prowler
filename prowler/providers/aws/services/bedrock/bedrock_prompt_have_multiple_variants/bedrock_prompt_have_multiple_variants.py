from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_agent_client import (
    bedrock_agent_client,
)


class bedrock_prompt_have_multiple_variants(Check):
    """Ensure that Bedrock prompts have multiple variants configured.

    This check evaluates whether each Bedrock prompt has more than one variant
    configured to enable A/B testing and improved resilience.
    - PASS: The Bedrock prompt has multiple variants configured.
    - FAIL: The Bedrock prompt has fewer than 2 variants configured.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock prompt multiple variants check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for prompt in bedrock_agent_client.prompts.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=prompt)
            report.status = "FAIL"
            num_variants = len(prompt.variants)
            report.status_extended = f"Bedrock Prompt {prompt.name} has only {num_variants} variant{'s' if num_variants != 1 else ''} configured, multiple variants are recommended for A/B testing and resilience."
            if num_variants > 1:
                report.status = "PASS"
                report.status_extended = f"Bedrock Prompt {prompt.name} has {num_variants} variants configured for A/B testing and resilience."
            findings.append(report)
        return findings
