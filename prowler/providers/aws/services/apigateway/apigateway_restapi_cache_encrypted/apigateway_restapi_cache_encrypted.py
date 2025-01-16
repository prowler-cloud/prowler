from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_restapi_cache_encrypted(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            for stage in rest_api.stages:
                if stage.cache_enabled:
                    report = Check_Report_AWS(
                        metadata=self.metadata(), resource_metadata=stage
                    )
                    report.region = rest_api.region
                    report.resource_id = rest_api.name
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has cache encryption enabled."
                    if not stage.cache_data_encrypted:
                        report.status = "FAIL"
                        report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has cache enabled but cache data is not encrypted at rest."
                    findings.append(report)

        return findings
