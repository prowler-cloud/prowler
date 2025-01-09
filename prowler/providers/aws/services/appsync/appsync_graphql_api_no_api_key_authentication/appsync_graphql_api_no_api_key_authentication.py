from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appsync.appsync_client import appsync_client


class appsync_graphql_api_no_api_key_authentication(Check):
    def execute(self):
        findings = []
        for api in appsync_client.graphql_apis.values():
            if api.type == "GRAPHQL":
                report = Check_Report_AWS(self.metadata())
                report.region = api.region
                report.resource_id = api.id
                report.resource_arn = api.arn
                report.resource_tags = api.tags
                report.status = "PASS"
                report.status_extended = f"AppSync GraphQL API {api.name} is not using an API KEY for authentication."
                if api.authentication_type == "API_KEY":
                    report.status = "FAIL"
                    report.status_extended = f"AppSync GraphQL API {api.name} is using an API KEY for authentication."
                findings.append(report)

        return findings
