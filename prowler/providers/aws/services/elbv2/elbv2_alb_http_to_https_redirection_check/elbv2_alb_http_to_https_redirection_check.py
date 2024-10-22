from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_alb_http_to_https_redirection_check(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            if lb.type == 'application':
                for listener in lb.listeners.values():
                    if listener.protocol == 'HTTP':
                        has_redirect = False
                        for rule in listener.rules:
                            for action in rule.actions:
                                if action['Type'] == 'redirect' and action['RedirectConfig']['Protocol'] == 'HTTPS':
                                    has_redirect = True
                                    break
                            if has_redirect:
                                break

                        report = Check_Report_AWS(self.metadata())
                        report.region = lb.region
                        report.resource_id = lb.name
                        report.resource_arn = lb.arn
                        report.resource_tags = lb.tags
                        report.status = "PASS" if has_redirect else "FAIL"
                        report.status_extended = (
                            f"ELBv2 ALB {lb.name} HTTP listener {listener.port} "
                            f"{'has' if has_redirect else 'does not have'} HTTP to HTTPS redirection configured."
                        )
                        findings.append(report)
        return findings
