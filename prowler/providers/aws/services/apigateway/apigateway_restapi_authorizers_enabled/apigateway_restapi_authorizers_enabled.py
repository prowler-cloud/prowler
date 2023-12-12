from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_restapi_authorizers_enabled(Check):
    def execute(self):
        findings = []
        for rest_api in apigateway_client.rest_apis:
            report = Check_Report_AWS(self.metadata())
            report.region = rest_api.region
            report.resource_id = rest_api.name
            report.resource_arn = rest_api.arn
            report.resource_tags = rest_api.tags
            report.status = "FAIL"
            report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} does not have an authorizer configured at api or methods level."
            if rest_api.authorizer:
                report.status = "PASS"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has an authorizer configured at api or methods scope."
            else:
                # we want to know if api has not authorizers and all the resources don't have methods configured
                api_resources_with_all_methods_authorized = False
                for resource in rest_api.resources:
                    # if the resource has methods test if they have all configured authorizer
                    if resource.resource_methods:
                        if "NONE" not in resource.resource_methods.values():
                            api_resources_with_all_methods_authorized = True
                        else:
                            # with only one unauthorized method -> return FAIL
                            api_resources_with_all_methods_authorized = False
                            break

                if api_resources_with_all_methods_authorized:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has an authorizer configured at api or methods level."

            findings.append(report)

        return findings
