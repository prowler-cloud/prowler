from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigatewayv2.apigatewayv2_client import (
    apigatewayv2_client,
)


class apigatewayv2_authorizers_enabled(Check):
    def execute(self):
        findings = []
        for api in apigatewayv2_client.apis:
            report = Check_Report_AWS(self.metadata())
            report.region = api.region
            report.resource_id = api.name
            report.resource_arn = api.arn
            report.resource_tags = api.tags
            report.status = "FAIL"
            report.status_extended = (
                f"API Gateway V2 {api.name} ID {api.id} does not have an authorizer configured."
            )
            if api.authorizer:
                report.status = "PASS"
                report.status_extended = (
                    f"API Gateway V2 {api.name} ID {api.id} has authorizer an configured."
                )
            findings.append(report)

        return findings
