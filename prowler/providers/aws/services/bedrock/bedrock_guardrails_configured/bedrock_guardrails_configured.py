from pydantic.v1 import BaseModel, Field

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class BedrockRegionalGuardrails(BaseModel):
    id: str
    arn: str
    region: str
    tags: list = Field(default_factory=list)


class bedrock_guardrails_configured(Check):
    """Ensure Bedrock guardrails are configured in successfully scanned regions.

    This check verifies that at least one Amazon Bedrock guardrail is configured
    in each successfully scanned region.
    - PASS: At least one Bedrock guardrail is configured in the region.
    - FAIL: No Bedrock guardrails are configured in the region.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region in sorted(bedrock_client.guardrails_scanned_regions):
            resource = BedrockRegionalGuardrails(
                id="bedrock-guardrails",
                arn=f"arn:{bedrock_client.audited_partition}:bedrock:{region}:{bedrock_client.audited_account}:guardrail/summary",
                region=region,
            )
            report = Check_Report_AWS(metadata=self.metadata(), resource=resource)

            regional_guardrails = [
                guardrail
                for guardrail in bedrock_client.guardrails.values()
                if guardrail.region == region
            ]
            regional_guardrails.sort(key=lambda guardrail: guardrail.name)

            if regional_guardrails:
                guardrail_names = ", ".join(g.name for g in regional_guardrails)
                report.status = "PASS"
                report.status_extended = f"Bedrock has {len(regional_guardrails)} guardrail(s) configured in region {region}: {guardrail_names}."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock has no guardrails configured in region {region}."
                )

            findings.append(report)

        return findings
