from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_client_prevent_user_existence_errors(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            for user_pool_client in pool.user_pool_clients.values():
                report = Check_Report_AWS(self.metadata())
                report.region = user_pool_client.region
                report.resource_id = user_pool_client.id
                report.resource_arn = user_pool_client.arn
                report.resource_tags = pool.tags
                if user_pool_client.prevent_user_existence_errors == "ENABLED":
                    report.status = "PASS"
                    report.status_extended = f"User pool client {user_pool_client.name} prevents revealing users in existence errors."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"User pool client {user_pool_client.name} does not prevent revealing users in existence errors."
                findings.append(report)

        return findings
