from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_restapi_tracing_enabled(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            for stage in rest_api.stages:
                report = Check_Report_AWS(self.metadata())
                report.region = rest_api.region
                report.resource_id = rest_api.name
                report.resource_arn = stage.arn
                report.resource_tags = stage.tags
                report.status = "FAIL"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} does not have X-Ray tracing enabled."
                if stage.tracing_enabled:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has X-Ray tracing enabled."
                findings.append(report)

        return findings
