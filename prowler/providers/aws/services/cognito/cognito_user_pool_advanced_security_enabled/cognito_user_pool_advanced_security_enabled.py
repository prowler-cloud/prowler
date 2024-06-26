from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client


class cognito_user_pool_advanced_security_enabled(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            if pool.advanced_security_mode == "ENFORCED":
                report.status = "PASS"
                report.status_extended = f"User pool {pool.name} has advanced security enforced with full-function mode."
            elif pool.advanced_security_mode == "AUDIT":
                report.status = "FAIL"
                report.status_extended = f"User pool {pool.name} has advanced security enabled but with audit-only mode."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"User pool {pool.name} has advanced security disabled."
                )
            findings.append(report)

        return findings
