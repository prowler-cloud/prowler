from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_identity_client import (
    cognito_identity_client,
)


class cognito_identity_pool_guest_access_disabled(Check):
    def execute(self):
        findings = []
        for identity_pool in cognito_identity_client.identity_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = identity_pool.region
            report.resource_id = identity_pool.id
            report.resource_arn = identity_pool.arn
            report.resource_tags = identity_pool.tags
            report.status = "PASS"
            report.status_extended = (
                f"Identity pool {identity_pool.id} has guest access disabled."
            )
            if identity_pool.allow_unauthenticated_identities:
                report.status = "FAIL"
                report.status_extended = (
                    f"Identity pool {identity_pool.name} has guest access enabled."
                )
                if identity_pool.roles.unauthenticated:
                    report.status_extended = f"Identity pool {identity_pool.name} has guest access enabled assuming the role {identity_pool.roles.unauthenticated}."
            findings.append(report)

        return findings
