from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_blocks_potential_malicious_sign_in_attempts(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            if pool.advanced_security_mode == "ENFORCED" and all(
                [
                    pool.risk_configuration.account_takeover_risk_configuration.low_action
                    and pool.risk_configuration.account_takeover_risk_configuration.low_action
                    == "BLOCK",
                    pool.risk_configuration.account_takeover_risk_configuration.medium_action
                    and pool.risk_configuration.account_takeover_risk_configuration.medium_action
                    == "BLOCK",
                    pool.risk_configuration.account_takeover_risk_configuration.high_action
                    and pool.risk_configuration.account_takeover_risk_configuration.high_action
                    == "BLOCK",
                ]
            ):
                report.status = "PASS"
                report.status_extended = f"User pool {pool.name} blocks all potential malicious sign-in attempts."
            else:
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.name} does not block all potential malicious sign-in attempts."
            findings.append(report)

        return findings
