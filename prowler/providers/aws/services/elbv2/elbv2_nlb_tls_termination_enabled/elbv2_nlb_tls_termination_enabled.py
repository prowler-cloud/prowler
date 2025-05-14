from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elbv2.elbv2_client import elbv2_client


class elbv2_nlb_tls_termination_enabled(Check):
    def execute(self):
        findings = []
        for lb in elbv2_client.loadbalancersv2.values():
            if lb.type == "network":
                report = Check_Report_AWS(metadata=self.metadata(), resource=lb)
                report.status = "FAIL"
                report.status_extended = f"ELBv2 NLB {lb.name} is not configured to terminate TLS connections."
                for listener in lb.listeners.values():
                    if listener.protocol == "TLS":
                        report.status = "PASS"
                        report.status_extended = f"ELBv2 NLB {lb.name} is configured to terminate TLS connections."

                findings.append(report)

        return findings
