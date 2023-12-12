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
            report.status_extended = f"API Gateway {rest_api.name} ({rest_api.id}) does not have authorizers configured for the following:"
            if rest_api.authorizer:
                report.status = "PASS"
                report.status_extended = f"API Gateway {rest_api.name} ({rest_api.id}) has an authorizer configured at the API level"
            else:
                # we want to know if api has not authorizers and all the resources don't have methods configured
                paths_without_authorizers = {}
                for resource in rest_api.resources:
                    # if the resource has methods test if they have all configured authorizer
                    if resource.resource_methods:
                        unauthorized_methods = [
                            method
                            for method, authorizer in resource.resource_methods.items()
                            if authorizer == "NONE" and not method == "OPTIONS"
                        ]
                        if unauthorized_methods:
                            paths_without_authorizers[
                                resource.path
                            ] = unauthorized_methods

                if paths_without_authorizers:
                    report.status = "FAIL"
                    failed_status_parts = []
                    for path, methods in paths_without_authorizers.items():
                        methods_str = ", ".join(methods)
                        if len(methods) == 1:
                            failed_status_parts.append(
                                f"{path} without authorizer for the {methods_str} method"
                            )
                        else:
                            failed_status_parts.append(
                                f"{path} without authorizers for {methods_str} methods"
                            )
                    failed_status_string = "; ".join(failed_status_parts)
                    report.status_extended = f"API Gateway {rest_api.name} ({rest_api.id}) issues: {failed_status_string}"
                else:
                    report.status = "PASS"
                    report.status_extended = f"API Gateway {rest_api.name} ({rest_api.id}) has all methods authorized."

            findings.append(report)

        return findings
