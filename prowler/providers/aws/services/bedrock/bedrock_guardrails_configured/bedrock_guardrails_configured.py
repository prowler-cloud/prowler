from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


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
            regional_guardrails = sorted(
                (
                    guardrail
                    for guardrail in bedrock_client.guardrails.values()
                    if guardrail.region == region
                ),
                key=lambda guardrail: guardrail.name,
            )

            if regional_guardrails:
                for guardrail in regional_guardrails:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource=guardrail
                    )
                    report.status = "PASS"
                    report.status_extended = f"Bedrock guardrail {guardrail.name} is available in region {region}. This does not confirm that the guardrail is attached to agents or used on model invocations."
                    findings.append(report)
            else:
                report = Check_Report_AWS(metadata=self.metadata(), resource={})
                report.region = region
                report.resource_id = "bedrock-guardrails"
                report.resource_arn = f"arn:{bedrock_client.audited_partition}:bedrock:{region}:{bedrock_client.audited_account}:guardrails"
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock has no guardrails configured in region {region}."
                )
                findings.append(report)

        return findings
