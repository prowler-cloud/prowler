from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_client_certificate_enabled(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            for stage in rest_api.stages:
                report = Check_Report_AWS(self.metadata())
                if stage.client_certificate:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has client certificate enabled."
                    report.resource_id = rest_api.name
                    report.region = rest_api.region
                else:
                    report.status = "FAIL"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has not client certificate enabled."
                    report.resource_id = rest_api.name
                    report.region = rest_api.region
                findings.append(report)

        return findings
