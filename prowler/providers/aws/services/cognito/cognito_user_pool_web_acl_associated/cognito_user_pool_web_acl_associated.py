from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cognito.cognito_idp_client import cognito_idp_client
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class cognito_user_pool_web_acl_associated(Check):
    def execute(self):
        findings = []
        for pool in cognito_idp_client.user_pools.values():
            report = Check_Report_AWS(self.metadata())
            report.region = pool.region
            report.resource_name = pool.name
            report.resource_id = pool.id
            report.resource_arn = pool.arn
            report.resource_tags = pool.tags
            has_association = False
            acl_associated = ""
            for acl in wafv2_client.web_acls:
                for user_pool in acl.user_pools:
                    if (
                        "userpool/" in user_pool
                        and user_pool.split("userpool/")[1] == pool.id
                    ):
                        has_association = True
                        acl_associated = acl.name
                        break
            if has_association:
                report.status = "PASS"
                report.status_extended = (
                    f"Cognito User Pool is associated with the Web ACL {acl_associated}"
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "Cognito User Pool is not associated with a Web ACL"
                )
            findings.append(report)

        return findings
