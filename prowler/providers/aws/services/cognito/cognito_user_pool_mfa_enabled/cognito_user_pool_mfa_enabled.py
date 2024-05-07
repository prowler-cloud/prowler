from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_mfa_enabled(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            if pool.mfa_config and pool.mfa_config.status == "ON":
                report.status = "PASS"
                report.status_extended = f"User pool {pool.name} has MFA enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.name} has MFA disabled."
            findings.append(report)

        return findings
