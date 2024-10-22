from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import apigateway_client


class apigateway_ssl_enabled(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            for stage in rest_api.stages:
                report = self._create_report(rest_api, stage)
                findings.append(report)
        return findings

    def _create_report(self, rest_api, stage):
        report = Check_Report_AWS(self.metadata())
        report.region = rest_api.region
        report.resource_id = f"{rest_api.name} - {stage.name}"
        report.resource_arn = stage.arn
        report.resource_tags = rest_api.tags

        if stage.ssl_certificate:
            report.status = "PASS"
            report.status_extended = f"API Gateway {rest_api.name} stage {stage.name} uses an SSL certificate."
        else:
            report.status = "FAIL"
            report.status_extended = f"API Gateway {rest_api.name} stage {stage.name} does not have an associated SSL certificate."

        return report
