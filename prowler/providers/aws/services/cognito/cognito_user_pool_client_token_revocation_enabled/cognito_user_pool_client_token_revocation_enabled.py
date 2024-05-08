from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_client_token_revocation_enabled(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            for pool_client in pool.user_pool_clients.values():
                report = Check_Report_AWS(self.metadata())
                report.region = pool_client.region
                report.resource_id = pool_client.id
                report.resource_arn = pool_client.arn
                report.resource_tags = pool.tags
                if pool_client.enable_token_revocation:
                    report.status = "PASS"
                    report.status_extended = f"User pool client {pool_client.name} has token revocation enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"User pool client {pool_client.name} has token revocation disabled."
                findings.append(report)

        return findings
