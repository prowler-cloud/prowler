from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_authorizers_enabled(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            report = Check_Report_AWS(self.metadata())
            report.region = rest_api.region
            if rest_api.authorizer:
                report.status = "PASS"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has authorizer configured."
                report.resource_id = rest_api.name
            else:
                report.status = "FAIL"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has not authorizer configured."
                report.resource_id = rest_api.name
            findings.append(report)

        return findings
