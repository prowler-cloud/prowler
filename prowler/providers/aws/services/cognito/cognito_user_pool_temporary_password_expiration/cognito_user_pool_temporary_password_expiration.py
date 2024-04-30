from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_temporary_password_expiration(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_name = pool.name
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            if pool.password_policy:
                if pool.password_policy.get("TemporaryPasswordValidityDays", 8) <= 7:
                    report.status = "PASS"
                    report.status_extended = f"User pool {pool.id} has temporary password expiration set to {pool.password_policy['TemporaryPasswordValidityDays']} days."
                else:
                    report.status = "FAIL"
                    report.status_extended = f"User pool {pool.id} has temporary password expiration set to {pool.password_policy['TemporaryPasswordValidityDays']} days."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"User pool {pool.id} has not password policy set."
                )
            findings.append(report)

        return findings
