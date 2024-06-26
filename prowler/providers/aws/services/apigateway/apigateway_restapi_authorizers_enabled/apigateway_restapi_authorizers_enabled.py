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
            # it there are not authorizers at api level and resources without methods (default case) ->
            report.status = "FAIL"
            report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} does not have an authorizer configured at api level."
            if rest_api.authorizer:
                report.status = "PASS"
                report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has an authorizer configured at api level"
            else:
                # we want to know if api has not authorizers and all the resources don't have methods configured
                resources_have_methods = False
                all_methods_authorized = True
                resource_paths_with_unathorized_methods = []
                for resource in rest_api.resources:
                    # if the resource has methods test if they have all configured authorizer
                    if resource.resource_methods:
                        resources_have_methods = True
                        for (
                            http_method,
                            authorization_method,
                        ) in resource.resource_methods.items():
                            if authorization_method == "NONE":
                                all_methods_authorized = False
                                unauthorized_method = (
                                    f"{resource.path} -> {http_method}"
                                )
                                resource_paths_with_unathorized_methods.append(
                                    unauthorized_method
                                )
                # if there are methods in at least one resource and are all authorized
                if all_methods_authorized and resources_have_methods:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} has all methods authorized"
                # if there are methods in at least one result but some of then are not authorized-> list it
                elif not all_methods_authorized:
                    report.status_extended = f"API Gateway {rest_api.name} ID {rest_api.id} does not have authorizers at api level and the following paths and methods are unauthorized: {'; '.join(resource_paths_with_unathorized_methods)}."

            findings.append(report)

        return findings
