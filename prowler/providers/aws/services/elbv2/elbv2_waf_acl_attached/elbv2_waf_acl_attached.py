from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client
from prowler.providers.aws.services.waf.wafregional_client import wafregional_client
from prowler.providers.aws.services.wafv2.wafv2_client import wafv2_client


class elbv2_waf_acl_attached(Check):
    def execute(self):
        findings = []
        for lb_arn, lb in elbv2_client.loadbalancersv2.items():
            if lb.type == "application":
                report = Check_Report_AWS(self.metadata())
                report.region = lb.region
                report.resource_id = lb.name
                report.resource_arn = lb_arn
                report.resource_tags = lb.tags
                report.status = "FAIL"
                report.status_extended = (
                    f"ELBv2 ALB {lb.name} is not protected by WAF Web ACL."
                )
                for acl in wafv2_client.web_acls.values():
                    if lb_arn in acl.albs:
                        report.status = "PASS"
                        report.status_extended = f"ELBv2 ALB {lb.name} is protected by WAFv2 Web ACL {acl.name}."
                for acl in wafregional_client.web_acls.values():
                    if lb_arn in acl.albs:
                        report.status = "PASS"
                        report.status_extended = f"ELBv2 ALB {lb.name} is protected by WAFv1 Web ACL {acl.name}."

                findings.append(report)

        return findings
