from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_identity_client import (
    cognito_identity_client,
)
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_self_registration_enabled(Check):
    def execute(self):
        findings = []
        for user_pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = user_pool.region
            report.resource_name = user_pool.name
            report.resource_id = user_pool.id
            report.resource_arn = user_pool.arn
            report.status = "PASS"
            report.status_extended = (
                f"User pool {user_pool.id} has self registration disabled."
            )
            if not user_pool.admin_create_user_config.get("AllowAdminCreateUserOnly"):
                report.status = "FAIL"
                report.status_extended = (
                    f"User pool {user_pool.id} has self registration enabled."
                )
                associated_identity_pools = []
                for identity_pool in cognito_identity_client.identity_pools.values():
                    for associated_pool in identity_pool.associated_pools.values():
                        if (
                            f"cognito-idp.{user_pool.region}.amazonaws.com/{user_pool.id}"
                            == associated_pool
                        ):
                            associated_identity_pools.append(identity_pool.name)
                if associated_identity_pools:
                    report.status_extended = f"User pool {user_pool.id} has self registration enabled and is associated with the following identity pools: {(', ').join(associated_identity_pools)}"
            findings.append(report)

        return findings
