from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_insecure_ssl_ciphers(Check):
    def execute(self):
        findings = []
        secure_ssl_policies = [
            "ELBSecurityPolicy-TLS-1-2-2017-01",
        ]
        for lb in elb_client.loadbalancers:
            report = Check_Report_AWS(self.metadata())
            report.region = lb.region
            report.resource_id = lb.name
            report.status = "PASS"
            report.status_extended = (
                f"ELB {lb.name} has not insecure SSL protocols or ciphers."
            )
            for listener in lb.listeners:
                if listener.protocol == "HTTPS" and not any(
                    check in listener.policies for check in secure_ssl_policies
                ):
                    report.status = "FAIL"
                    report.status_extended = f"ELB {lb.name} has listeners with insecure SSL protocols or ciphers."

            findings.append(report)

        return findings
