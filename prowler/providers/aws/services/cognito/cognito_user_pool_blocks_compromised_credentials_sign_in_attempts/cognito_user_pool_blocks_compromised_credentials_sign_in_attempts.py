from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_blocks_compromised_credentials_sign_in_attempts(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            if (
                pool.advanced_security_mode == "ENFORCED"
                and "SIGN_IN"
                in pool.risk_configuration.compromised_credentials_risk_configuration.event_filter
                and pool.risk_configuration.compromised_credentials_risk_configuration.actions
                == "BLOCK"
            ):
                report.status = "PASS"
                report.status_extended = f"User pool {pool.name} blocks sign-in attempts with suspected compromised credentials."
            else:
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.name} does not block sign-in attempts with suspected compromised credentials."
            findings.append(report)

        return findings
