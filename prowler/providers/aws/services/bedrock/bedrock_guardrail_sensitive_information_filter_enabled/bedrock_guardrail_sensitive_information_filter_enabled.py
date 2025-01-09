from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_guardrail_sensitive_information_filter_enabled(Check):
    def execute(self):
        findings = []
        for guardrail in bedrock_client.guardrails.values():
            report = Check_Report_AWS(self.metadata())
            report.region = guardrail.region
            report.resource_id = guardrail.id
            report.resource_arn = guardrail.arn
            report.resource_tags = guardrail.tags
            report.status = "PASS"
            report.status_extended = f"Bedrock Guardrail {guardrail.name} is blocking or masking sensitive information."
            if not guardrail.sensitive_information_filter:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} is not configured to block or mask sensitive information."
            findings.append(report)

        return findings
