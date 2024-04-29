from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_advanced_security_adaptative_authentication_block_sign_in(
    Check
):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_name = pool.name
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            if (
                pool.advanced_security_mode == "ENFORCED"
                and pool.risk_configuration.account_takeover_risk_configuration.get(
                    "Actions"
                )
                .get("LowAction")
                .get("EventAction")
                == "BLOCK"
                and pool.risk_configuration.account_takeover_risk_configuration.get(
                    "Actions"
                )
                .get("MediumAction")
                .get("EventAction")
                == "BLOCK"
                and pool.risk_configuration.account_takeover_risk_configuration.get(
                    "Actions"
                )
                .get("HighAction")
                .get("EventAction")
                == "BLOCK"
            ):
                report.status = "PASS"
                report.status_extended = f"User pool {pool.id} has advanced security enforced with adaptative authentication sign-in blocked."
            else:
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.id} does not have advanced security enforced with adaptative authentication sign-in blocked."
            findings.append(report)

        return findings
