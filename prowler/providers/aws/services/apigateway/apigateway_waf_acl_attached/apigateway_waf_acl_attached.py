from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_waf_acl_attached(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            report = Check_Report_AWS(self.metadata())
            report.region = rest_api.region
            for stage in rest_api.stages:
                if stage.waf:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has {stage.waf} WAF ACL attached."
                    report.resource_id = rest_api.name
                else:
                    report.status = "FAIL"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} in stage {stage.name} has not WAF ACL attached."
                    report.resource_id = rest_api.name
                findings.append(report)

        return findings
