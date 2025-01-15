from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elb.elb_client import elb_client


class elb_ssl_listeners(Check):
    def execute(self):
        findings = []
        secure_protocols = ["SSL", "HTTPS"]
        for lb in elb_client.loadbalancers.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource_metadata=lb)
            report.status = "PASS"
            report.status_extended = f"ELB {lb.name} has HTTPS listeners only."
            for listener in lb.listeners:
                if listener.protocol not in secure_protocols:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"ELB {lb.name} has non-encrypted listeners."
                    )

            findings.append(report)

        return findings
