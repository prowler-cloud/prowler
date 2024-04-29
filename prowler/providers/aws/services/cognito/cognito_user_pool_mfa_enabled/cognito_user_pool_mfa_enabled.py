from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_mfa_enabled(Check):
    def execute(self):
        findings = []
        if any(pool.mfa_config for pool in cognito_idp_client.user_pools.values()):
            for pool in cognito_idp_client.user_pools.values():
                report = Check_Report_AWS(self.metadata())
                report.region = pool.region
                report.resource_name = pool.name
                report.resource_id = pool.id
                report.resource_arn = pool.arn
                if pool.mfa_config and pool.mfa_config.status == "ON":
                    report.status = "PASS"
                    report.status_extended = f"User pool {pool.id} has MFA enabled."
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User pool {pool.id} does not have MFA enabled."
                    )
                findings.append(report)

        return findings
