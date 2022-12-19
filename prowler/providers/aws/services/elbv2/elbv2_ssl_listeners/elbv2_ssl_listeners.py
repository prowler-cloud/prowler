from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_ssl_listeners(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2:
            if lb.type == "application":
                report = Check_Report_AWS(self.metadata())
                report.region = lb.region
                report.resource_id = lb.name
                report.resource_arn = lb.arn
                report.status = "PASS"
                report.status_extended = (
                    f"ELBv2 ALB {lb.name} has HTTPS listeners only."
                )
                for listener in lb.listeners:
                    if listener.protocol == "HTTP":
                        report.status = "FAIL"
                        report.status_extended = (
                            f"ELBv2 ALB {lb.name} has non-encrypted listeners."
                        )
                        # Check if it redirects HTTP to HTTPS
                        for rule in listener.rules:
                            for action in rule.actions:
                                if (
                                    action["Type"] == "redirect"
                                    and action["RedirectConfig"]["Protocol"] == "HTTPS"
                                ):
                                    report.status = "PASS"
                                    report.status_extended = f"ELBv2 ALB {lb.name} has HTTP listener but it redirects to HTTPS."

                findings.append(report)

        return findings
