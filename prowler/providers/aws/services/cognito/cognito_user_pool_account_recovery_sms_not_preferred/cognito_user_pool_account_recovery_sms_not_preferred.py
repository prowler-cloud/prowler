from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_account_recovery_sms_not_preferred(Check):
    """Verify that user pools do not prefer SMS for account recovery.

    A pool PASSES when the recovery mechanism with the lowest ``Priority`` is
    something other than ``verified_phone_number``. A pool with no
    ``AccountRecoverySetting`` at all FAILS, because Amazon Cognito then applies
    the legacy behavior that prefers SMS over email.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Cognito user pool account recovery check.

        Returns:
            A list of reports with each user pool preferred recovery mechanism.
        """
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=pool)
            mechanisms = (pool.account_recovery_settings or {}).get(
                "RecoveryMechanisms", []
            )
            if not mechanisms:
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.name} does not define an account recovery setting, so SMS is preferred over email."
            else:
                preferred = min(mechanisms, key=lambda mechanism: mechanism["Priority"])
                if preferred["Name"] == "verified_phone_number":
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User pool {pool.name} prefers SMS for account recovery."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = f"User pool {pool.name} prefers {preferred['Name']} over SMS for account recovery."
            findings.append(report)

        return findings
