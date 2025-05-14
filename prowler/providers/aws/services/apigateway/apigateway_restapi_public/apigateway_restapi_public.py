from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_restapi_public(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            report = Check_Report_AWS(metadata=self.metadata(), resource=rest_api)
            report.resource_id = rest_api.name

            if rest_api.public_endpoint:
                report.status = "FAIL"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} is internet accessible."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"API Gateway {rest_api.name} ID {rest_api.id} is private."
                )
            findings.append(report)

        return findings
