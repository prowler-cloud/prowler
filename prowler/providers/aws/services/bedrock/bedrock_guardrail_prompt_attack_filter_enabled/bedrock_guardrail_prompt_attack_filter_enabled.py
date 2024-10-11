from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_guardrail_prompt_attack_filter_enabled(Check):
    def execute(self):
        findings = []
        for guardrail in bedrock_client.guardrails.values():
            report = Check_Report_AWS(self.metadata())
            report.region = guardrail.region
            report.resource_id = guardrail.id
            report.resource_arn = guardrail.arn
            report.status = "PASS"
            report.status_extended = f"Bedrock Guardrail {guardrail.name} is configured with a prompt attacks filter with a HIGH strength."
            if not guardrail.prompt_attack_filter_strength:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} is not configured with a prompt attacks filter."
            elif guardrail.prompt_attack_filter_strength != "HIGH":
                report.status = "FAIL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} is not configured with a prompt attacks filter with a HIGH strength ({guardrail.prompt_attack_filter_strength})."
            findings.append(report)

        return findings
