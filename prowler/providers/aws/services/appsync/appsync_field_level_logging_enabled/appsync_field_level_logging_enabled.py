from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.appsync.appsync_client import appsync_client


class appsync_field_level_logging_enabled(Check):
    def execute(self):
        findings = []
        # Check only GraphQL APIs because boto3 does not have a method to get other types of AppSync APIs (list_apis is not working)
        for api in appsync_client.graphql_apis.values():
            report = Check_Report_AWS(self.metadata())
            report.region = api.region
            report.resource_id = api.id
            report.resource_arn = api.arn
            report.resource_tags = api.tags
            report.status = "PASS"
            report.status_extended = (
                f"AppSync API {api.name} has field log level enabled."
            )
            if api.field_log_level != "ALL" and api.field_log_level != "ERROR":
                report.status = "FAIL"
                report.status_extended = (
                    f"AppSync API {api.name} does not have field log level enabled."
                )
            findings.append(report)

        return findings
