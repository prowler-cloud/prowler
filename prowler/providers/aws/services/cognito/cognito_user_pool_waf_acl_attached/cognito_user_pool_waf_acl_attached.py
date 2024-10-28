from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class cognito_user_pool_waf_acl_attached(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Cognito User Pool {pool.name} is not associated with a WAF Web ACL."
            )
            for acl in wafv2_client.web_acls.values():
                if pool.arn in acl.user_pools:
                    report.status = "PASS"
                    report.status_extended = f"Cognito User Pool {pool.name} is associated with the WAF Web ACL {acl.name}."
                    break
            findings.append(report)

        return findings
